package amazonec2

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/docker/machine/libmachine/ssh"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/docker/machine/drivers/driverutil"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/state"
	"github.com/mitchellh/go-homedir"
)

const (
	driverName                  = "amazonec2"
	ipRange                     = "0.0.0.0/0"
	defaultInstanceType         = "r5a.large"
	defaultDeviceName           = "/dev/sda1"
	defaultRootSize             = 50
	defaultVolumeType           = "gp2"
	defaultSecurityGroup        = "internal"
	defaultSSHPort              = 22
	defaultSSHUser              = "ubuntu"
	defaultBlockDurationMinutes = 0
	defaultIamInstanceProfile   = "EC2"
)

const (
	keypairNotFoundCode             = "InvalidKeyPair.NotFound"
	spotInstanceRequestNotFoundCode = "InvalidSpotInstanceRequestID.NotFound"
)

var (
	dockerPort                           = 2376
	swarmPort                            = 3376
	errorNoUserEnv                       = errors.New("missing USER env and we require it for automation")
	errorNoPrivateSSHKey                 = errors.New("using --amazonec2-keypair-name also requires --amazonec2-ssh-keypath")
	errorMissingCredentials              = errors.New("amazonec2 driver requires AWS credentials configured with the --amazonec2-access-key and --amazonec2-secret-key options, environment variables, ~/.aws/credentials, or an instance role")
	errorNoVPCIdFound                    = errors.New("amazonec2 driver requires either the --amazonec2-subnet-id or --amazonec2-vpc-id option or an AWS Account with a default vpc-id")
	errorNoSubnetsFound                  = errors.New("The desired subnet could not be located in this region. Is '--amazonec2-subnet-id' or AWS_SUBNET_ID configured correctly?")
	errorDisableSSLWithoutCustomEndpoint = errors.New("using --amazonec2-insecure-transport also requires --amazonec2-endpoint")
	errorReadingUserData                 = errors.New("unable to read --amazonec2-userdata file")
)

type Driver struct {
	*drivers.BaseDriver
	ec2Client     *ec2.EC2
	ssmClient     *ssm.SSM
	pricingClient *pricing.Pricing

	Id               string
	Profile          string
	LoadConfig       session.SharedConfigState
	Region           string
	AMI              string
	AWSKeyID         string
	KeyName          string
	InstanceId       string
	InstanceType     string
	PrivateIPAddress string

	// NB: SecurityGroupId expanded from single value to slice on 26 Feb 2016 - we maintain both for host storage backwards compatibility.
	SecurityGroupId  string
	SecurityGroupIds []string

	// NB: SecurityGroupName expanded from single value to slice on 26 Feb 2016 - we maintain both for host storage backwards compatibility.
	SecurityGroupName  string
	SecurityGroupNames []string

	SecurityGroupManage   bool
	OpenPorts             []string
	Tags                  string
	ReservationId         string
	DeviceName            string
	RootSize              int64
	VolumeType            string
	IamInstanceProfile    string
	VpcId                 string
	SubnetId              string
	keyPath               string
	RequestSpotInstance   bool
	SpotPrice             string
	BlockDurationMinutes  int64
	UsePublicIp           bool
	Monitoring            bool
	SSHPrivateKeyPath     string
	RetryCount            int
	Endpoint              string
	DisableSSL            bool
	UserDataFile          string
	SpotInstanceRequestId string
	ssmParamterVPCId      string
	ssmParamterSubnedId   string
	runningIP             string
	foundKeyWhileCreate   bool
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "amazonec2-ami",
			Usage:  "AWS machine image",
			EnvVar: "AWS_AMI",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-vpc-id",
			Usage:  "AWS VPC id",
			EnvVar: "AWS_VPC_ID",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-ssm-parameter-vpc-id",
			Usage:  "AWS SSM Parameter Key for VPC ID",
			EnvVar: "AWS_SSM_PARAMETER_VPC_ID",
			Value:  "/config/networking/default/vpc_id",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-subnet-id",
			Usage:  "AWS VPC subnet id",
			EnvVar: "AWS_SUBNET_ID",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-ssm-parameter-subnet-id",
			Usage:  "AWS SSM Parameter Key for VPC subnet id",
			EnvVar: "AWS_SSM_PARAMETER_SUBNET_ID",
			Value:  "/config/networking/default/private-subnets",
		},
		mcnflag.BoolFlag{
			Name:   "amazonec2-security-group-manage",
			Usage:  "Add default rules to security groups",
			EnvVar: "AWS_SECURITY_GROUP_MANAGE",
		},
		mcnflag.StringSliceFlag{
			Name:   "amazonec2-security-group",
			Usage:  "AWS VPC security group",
			Value:  []string{defaultSecurityGroup},
			EnvVar: "AWS_SECURITY_GROUP",
		},
		mcnflag.StringSliceFlag{
			Name:  "amazonec2-open-port",
			Usage: "Make the specified port number accessible from the Internet",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-tags",
			Usage:  "AWS Tags (e.g. key1,value1,key2,value2)",
			EnvVar: "AWS_TAGS",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-instance-type",
			Usage:  "AWS instance type",
			Value:  defaultInstanceType,
			EnvVar: "AWS_INSTANCE_TYPE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-device-name",
			Usage:  "AWS root device name",
			Value:  defaultDeviceName,
			EnvVar: "AWS_DEVICE_NAME",
		},
		mcnflag.IntFlag{
			Name:   "amazonec2-root-size",
			Usage:  "AWS root disk size (in GB)",
			Value:  defaultRootSize,
			EnvVar: "AWS_ROOT_SIZE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-volume-type",
			Usage:  "Amazon EBS volume type",
			Value:  defaultVolumeType,
			EnvVar: "AWS_VOLUME_TYPE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-iam-instance-profile",
			Usage:  "AWS IAM Instance Profile",
			Value:  defaultIamInstanceProfile,
			EnvVar: "AWS_INSTANCE_PROFILE",
		},
		mcnflag.IntFlag{
			Name:   "amazonec2-ssh-port",
			Usage:  "SSH port",
			Value:  defaultSSHPort,
			EnvVar: "AWS_SSH_PORT",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-ssh-user",
			Usage:  "SSH username",
			Value:  defaultSSHUser,
			EnvVar: "AWS_SSH_USER",
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-request-spot-instance",
			Usage: "Set this flag to request spot instance",
		},
		mcnflag.StringFlag{
			Name:  "amazonec2-spot-price",
			Usage: "AWS spot instance bid price (in dollar)",
		},
		mcnflag.IntFlag{
			Name:  "amazonec2-block-duration-minutes",
			Usage: "AWS spot instance duration in minutes (60, 120, 180, 240, 300, or 360)",
			Value: defaultBlockDurationMinutes,
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-use-public-address",
			Usage: "Only use a Public IP address",
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-monitoring",
			Usage: "Set this flag to enable CloudWatch monitoring",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-ssh-keypath",
			Usage:  "File path to Private SSH Key to use with machine. The public key is expected to exist in the same place with .pub extension",
			EnvVar: "AWS_SSH_KEYPATH",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-keypair-name",
			Usage:  "AWS keypair name to use. Raw value is used when used in combination with --amazonec2-ssh-keypath, otherwise 'amazonec2-' prefix is always added to supplied value",
			EnvVar: "AWS_KEYPAIR_NAME",
		},
		mcnflag.IntFlag{
			Name:  "amazonec2-retries",
			Usage: "Set retry count for recoverable failures (use -1 to disable)",
			Value: 5,
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-endpoint",
			Usage:  "Optional endpoint URL (hostname only or fully qualified URI)",
			Value:  "",
			EnvVar: "AWS_ENDPOINT",
		},
		mcnflag.BoolFlag{
			Name:   "amazonec2-insecure-transport",
			Usage:  "Disable SSL when sending requests",
			EnvVar: "AWS_INSECURE_TRANSPORT",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-userdata",
			Usage:  "path to file with cloud-init user data",
			EnvVar: "AWS_USERDATA",
		},
	}
}

func NewDriver(hostName, storePath string) *Driver {
	id := generateId()
	driver := &Driver{
		Id:                   id,
		InstanceType:         defaultInstanceType,
		RootSize:             defaultRootSize,
		SecurityGroupNames:   []string{defaultSecurityGroup},
		BlockDurationMinutes: defaultBlockDurationMinutes,
		BaseDriver: &drivers.BaseDriver{
			SSHPort:     defaultSSHPort,
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return driver
}

func (d *Driver) createAWSOpts(region string) session.Options {
	config := aws.NewConfig()
	alogger := AwsLogger()
	config = config.WithRegion(region)
	config = config.WithLogger(alogger)
	config = config.WithLogLevel(aws.LogDebugWithHTTPBody)
	config = config.WithMaxRetries(d.RetryCount)
	if d.Endpoint != "" {
		config = config.WithEndpoint(d.Endpoint)
		config = config.WithDisableSSL(d.DisableSSL)
	}
	config = config.WithCredentialsChainVerboseErrors(true)

	opts := session.Options{}
	opts.Config.MergeIn(config)
	if d.Profile == "" {
		panic(fmt.Errorf("oh no, no profile, that means this won't work at all"))
	}
	opts.Profile = d.Profile
	opts.SharedConfigState = d.LoadConfig

	return opts
}

func (d *Driver) getEC2Client() *ec2.EC2 {
	if d.ec2Client != nil {
		return d.ec2Client
	}
	opts := d.createAWSOpts(d.Region)
	sess, err := session.NewSessionWithOptions(opts)
	if err != nil {
		panic(err)
	}
	// on the occasion region isn't set in the driver, snag it from our new ec2 session.
	if d.Region == "" {
		d.Region = *sess.Config.Region
	}
	d.ec2Client = ec2.New(sess)

	return d.ec2Client
}

func (d *Driver) getSSMClient() *ssm.SSM {
	if d.ssmClient != nil {
		return d.ssmClient
	}
	opts := d.createAWSOpts(d.Region)
	sess, err := session.NewSessionWithOptions(opts)
	if err != nil {
		panic(err)
	}
	// on the occasion region isn't set in the driver, snag it from our new ec2 session.
	if d.Region == "" {
		d.Region = *sess.Config.Region
	}
	d.ssmClient = ssm.New(sess)

	return d.ssmClient
}

func (d *Driver) getPricingClient() *pricing.Pricing {
	if d.pricingClient != nil {
		return d.pricingClient
	}
	// pricing api only exists in us-east-1 and ap-south-1
	// https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/using-pelong.html#pe-endpoint
	opts := d.createAWSOpts("us-east-1")
	sess, err := session.NewSessionWithOptions(opts)
	if err != nil {
		panic(err)
	}
	d.pricingClient = pricing.New(sess)

	return d.pricingClient
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.DisableSSL = flags.Bool("amazonec2-insecure-transport")
	d.Endpoint = flags.String("amazonec2-endpoint")
	if d.DisableSSL && d.Endpoint == "" {
		return errorDisableSSLWithoutCustomEndpoint
	}
	d.AMI = flags.String("amazonec2-ami")
	d.RequestSpotInstance = flags.Bool("amazonec2-request-spot-instance")
	d.SpotPrice = flags.String("amazonec2-spot-price")
	d.BlockDurationMinutes = int64(flags.Int("amazonec2-block-duration-minutes"))
	d.InstanceType = flags.String("amazonec2-instance-type")
	d.VpcId = flags.String("amazonec2-vpc-id")
	d.ssmParamterVPCId = flags.String("amazonec2-ssm-parameter-vpc-id")
	d.SubnetId = flags.String("amazonec2-subnet-id")
	d.ssmParamterSubnedId = flags.String("amazonec2-ssm-parameter-subnet-id")
	d.SecurityGroupNames = flags.StringSlice("amazonec2-security-group")
	d.SecurityGroupManage = flags.Bool("amazonec2-security-group-manage")
	d.Tags = flags.String("amazonec2-tags")
	if d.Tags == "" {
		user, userOk := os.LookupEnv("USER")
		var tags []string
		if userOk {
			tags = append(tags, fmt.Sprintf("Name,%s-%s", d.GetMachineName(), user))
			tags = append(tags, fmt.Sprintf("owner,%s", user))
		}
		tags = append(tags, "madeby,docker-machine,customer,development,purpose,development")
		d.Tags = strings.Join(tags, ",")
	}
	d.DeviceName = flags.String("amazonec2-device-name")
	d.RootSize = int64(flags.Int("amazonec2-root-size"))
	d.VolumeType = flags.String("amazonec2-volume-type")
	d.IamInstanceProfile = flags.String("amazonec2-iam-instance-profile")
	d.SSHUser = flags.String("amazonec2-ssh-user")
	d.SSHPort = flags.Int("amazonec2-ssh-port")
	d.UsePublicIp = flags.Bool("amazonec2-use-public-address")
	d.Monitoring = flags.Bool("amazonec2-monitoring")
	d.KeyName = flags.String("amazonec2-keypair-name")
	d.SSHPrivateKeyPath = flags.String("amazonec2-ssh-keypath")

	if d.KeyName != "" && d.SSHPrivateKeyPath != "" {
		log.Info("using raw values for KeyName and SSHPrivateKeyPath - good luck!")
	} else {

		// Always append our driver name to our keyname, and if we have no keyname, user our username
		if d.KeyName != "" {
			d.KeyName = fmt.Sprintf("%s-%s", driverName, d.KeyName)
		} else {
			user, userOk := os.LookupEnv("USER")
			if !userOk {
				return errorNoUserEnv
			}
			d.KeyName = fmt.Sprintf("%s-%s", driverName, user)
		}

		// if we don't specify a key to use, use our keyname.
		if d.SSHPrivateKeyPath == "" {
			hdir, err := homedir.Dir()
			if err != nil {
				return fmt.Errorf("could not get home dir, %v", err)
			}
			d.SSHPrivateKeyPath = filepath.Join(hdir, ".ssh", d.KeyName)
		}
	}

	d.RetryCount = flags.Int("amazonec2-retries")
	d.OpenPorts = flags.StringSlice("amazonec2-open-port")
	d.UserDataFile = flags.String("amazonec2-userdata")
	d.SetSwarmConfigFromFlags(flags)
	if d.isSwarmMaster() {
		u, err := url.Parse(d.SwarmHost)
		if err != nil {
			return fmt.Errorf("error parsing swarm host: %s", err)
		}

		parts := strings.Split(u.Host, ":")
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return err
		}

		swarmPort = port
	}

	if d.Profile == "" {
		// we do all this profile and shared config leg work so that we don't have to
		// specify these things again when using future commands, those commands should just work TM
		profile, ok := os.LookupEnv("AWS_PROFILE")
		if ok {
			d.Profile = profile
		}
	}

	if d.Profile == "" {
		// In case you use aws-vault, we'll grab the profile from this environment variable.
		profile, ok := os.LookupEnv("AWS_VAULT")
		if ok {
			d.Profile = profile
		}
	}

	loadConfig, ok := os.LookupEnv("AWS_SDK_LOAD_CONFIG")
	if ok {
		// Sometimes this language is miserable...
		loadInt, err := strconv.ParseBool(loadConfig)
		if err != nil {
			panic(err)
		}
		if loadInt {
			d.LoadConfig = session.SharedConfigEnable
		} else {
			d.LoadConfig = session.SharedConfigDisable
		}
	}
	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) checkPrereqs() error {
	// Now that we've set our config flags, we can use our client to be smart.

	if d.AMI == "" {
		resp, err := d.getEC2Client().DescribeImages(&ec2.DescribeImagesInput{
			Owners: aws.StringSlice([]string{"099720109477"}),
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("name"),
					Values: aws.StringSlice([]string{"ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-????????"}),
				},
				&ec2.Filter{
					Name:   aws.String("state"),
					Values: aws.StringSlice([]string{"available"}),
				},
			},
		})
		if err != nil {
			return err
		}
		sort.Slice(resp.Images, func(i, j int) bool {
			itime, _ := time.Parse(time.RFC3339, aws.StringValue(resp.Images[i].CreationDate))
			jtime, _ := time.Parse(time.RFC3339, aws.StringValue(resp.Images[j].CreationDate))
			return itime.Unix() > jtime.Unix()
		})
		d.AMI = *resp.Images[0].ImageId
		log.Infof("using AMI ID %s", d.AMI)
	}

	if d.RequestSpotInstance && d.SpotPrice == "" {
		input := &pricing.GetProductsInput{
			Filters: []*pricing.Filter{
				&pricing.Filter{
					Field: aws.String("usageType"),
					Type:  aws.String("TERM_MATCH"),
					Value: aws.String(fmt.Sprintf("USW2-BoxUsage:%s", d.InstanceType)),
				},
				&pricing.Filter{
					Field: aws.String("operatingSystem"),
					Type:  aws.String("TERM_MATCH"),
					Value: aws.String("linux"),
				},
				&pricing.Filter{
					Field: aws.String("preInstalledSw"),
					Type:  aws.String("TERM_MATCH"),
					Value: aws.String("NA"),
				},
			},
			ServiceCode: aws.String("AmazonEC2"),
		}
		priceJSON, err := d.getPricingClient().GetProducts(input)
		if err != nil {
			return err
		}

		if len(priceJSON.PriceList) > 0 {
			raw := priceJSON.PriceList[0]
			var po ProductOffer
			b, err := json.Marshal(raw)
			if err != nil {
				panic(err)
			}
			err = json.Unmarshal(b, &po)
			if err != nil {
				panic(err)
			}

			stringInstancePrice := po.Terms.OnDemand[0].PriceDimensions[0].PricePerUnit.USD
			log.Infof("found instance price: %s", stringInstancePrice)

			instancePrice, err := strconv.ParseFloat(stringInstancePrice, 64)
			if err != nil {
				return err
			}
			inflatedPrice := instancePrice * 1.1
			d.SpotPrice = fmt.Sprintf("%f", inflatedPrice)
		}
		log.Infof("using spot price: %s", d.SpotPrice)
	}

	if d.VpcId == "" {
		if d.ssmParamterVPCId != "" {
			param, err := d.getSSMClient().GetParameter(&ssm.GetParameterInput{Name: aws.String(d.ssmParamterVPCId)})
			if err != nil {
				return err
			}
			d.VpcId = *param.Parameter.Value
			log.Infof("using VPC ID %s", d.VpcId)
		}
	}

	if d.SubnetId == "" {
		if d.ssmParamterSubnedId != "" {
			param, err := d.getSSMClient().GetParameter(&ssm.GetParameterInput{Name: aws.String(d.ssmParamterSubnedId)})
			if err != nil {
				return err
			}
			if *param.Parameter.Type == "StringList" {
				subnets := strings.Split(*param.Parameter.Value, ",")
				d.SubnetId = subnets[0]
			} else {
				d.SubnetId = *param.Parameter.Value
			}
			log.Infof("using Subnet ID %s", d.SubnetId)
		}
		if d.SubnetId == "" {
			filters := []*ec2.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []*string{&d.VpcId},
				},
			}

			subnets, err := d.getEC2Client().DescribeSubnets(&ec2.DescribeSubnetsInput{
				Filters: filters,
			})
			if err != nil {
				return err
			}

			if len(subnets.Subnets) == 0 {
				return fmt.Errorf("unable to find a subnet belonging to VPC ID %s", d.VpcId)
			}

			d.SubnetId = *subnets.Subnets[0].SubnetId

			// try to find default
			if len(subnets.Subnets) > 1 {
				for _, subnet := range subnets.Subnets {
					if subnet.DefaultForAz != nil && *subnet.DefaultForAz {
						d.SubnetId = *subnet.SubnetId
						break
					}
				}
			}
		}
	}

	// Is the found Subnet actually part of the VPC?
	if d.SubnetId != "" && d.VpcId != "" {
		subnetFilter := []*ec2.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []*string{&d.SubnetId},
			},
		}

		subnets, err := d.getEC2Client().DescribeSubnets(&ec2.DescribeSubnetsInput{
			Filters: subnetFilter,
		})
		if err != nil {
			return err
		}

		if subnets == nil || len(subnets.Subnets) == 0 {
			return errorNoSubnetsFound
		}

		if *subnets.Subnets[0].VpcId != d.VpcId {
			return fmt.Errorf("SubnetId: %s does not belong to VpcId: %s", d.SubnetId, d.VpcId)
		}
	}

	if d.KeyName != "" && d.SSHPrivateKeyPath == "" {
		return errorNoPrivateSSHKey
	}

	if d.KeyName == "" {
		d.KeyName = d.MachineName
	}

	return nil
}

func (d *Driver) PreCreateCheck() error {
	return d.checkPrereqs()
}

func (d *Driver) instanceIpAvailable() bool {
	ip, err := d.GetIP()
	if err != nil {
		log.Debug(err)
	}
	if ip != "" {
		d.IPAddress = ip
		log.Debugf("Got the IP Address, it's %q", d.IPAddress)
		return true
	}
	return false
}

func makePointerSlice(stackSlice []string) []*string {
	pointerSlice := []*string{}
	for i := range stackSlice {
		pointerSlice = append(pointerSlice, &stackSlice[i])
	}
	return pointerSlice
}

// Support migrating single string Driver fields to slices.
func migrateStringToSlice(value string, values []string) (result []string) {
	if value != "" {
		result = append(result, value)
	}
	result = append(result, values...)
	return
}

func (d *Driver) securityGroupNames() (ids []string) {
	return migrateStringToSlice(d.SecurityGroupName, d.SecurityGroupNames)
}

func (d *Driver) securityGroupIds() (ids []string) {
	return migrateStringToSlice(d.SecurityGroupId, d.SecurityGroupIds)
}

func (d *Driver) Base64UserData() (userdata string, err error) {
	if d.UserDataFile != "" {
		buf, ioerr := ioutil.ReadFile(d.UserDataFile)
		if ioerr != nil {
			log.Warnf("failed to read user data file %q: %s", d.UserDataFile, ioerr)
			err = errorReadingUserData
			return
		}
		userdata = base64.StdEncoding.EncodeToString(buf)
	}
	return
}

func (d *Driver) Create() error {
	if err := d.checkPrereqs(); err != nil {
		return err
	}

	if err := d.innerCreate(); err != nil {
		// cleanup partially created resources
		d.Remove()
		return err
	}

	return nil
}

func (d *Driver) innerCreate() error {
	log.Infof("Launching instance...")

	if err := d.createKeyPair(); err != nil {
		return fmt.Errorf("unable to create key pair: %s", err)
	}

	if err := d.configureSecurityGroups(d.securityGroupNames()); err != nil {
		return err
	}

	var userdata string
	if b64, err := d.Base64UserData(); err != nil {
		return err
	} else {
		userdata = b64
	}

	bdm := &ec2.BlockDeviceMapping{
		DeviceName: aws.String(d.DeviceName),
		Ebs: &ec2.EbsBlockDevice{
			VolumeSize:          aws.Int64(d.RootSize),
			VolumeType:          aws.String(d.VolumeType),
			DeleteOnTermination: aws.Bool(true),
		},
	}
	netSpecs := []*ec2.InstanceNetworkInterfaceSpecification{{
		DeviceIndex:              aws.Int64(0), // eth0
		Groups:                   makePointerSlice(d.securityGroupIds()),
		SubnetId:                 &d.SubnetId,
		AssociatePublicIpAddress: aws.Bool(d.UsePublicIp),
	}}

	log.Debugf("launching instance in subnet %s", d.SubnetId)

	var instance *ec2.Instance

	if d.RequestSpotInstance {
		req := ec2.RequestSpotInstancesInput{
			LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
				ImageId:           &d.AMI,
				KeyName:           &d.KeyName,
				InstanceType:      &d.InstanceType,
				NetworkInterfaces: netSpecs,
				Monitoring:        &ec2.RunInstancesMonitoringEnabled{Enabled: aws.Bool(d.Monitoring)},
				IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
					Name: &d.IamInstanceProfile,
				},
				BlockDeviceMappings: []*ec2.BlockDeviceMapping{bdm},
				UserData:            &userdata,
			},
			InstanceCount:                aws.Int64(1),
			InstanceInterruptionBehavior: aws.String("stop"),
			Type:                         aws.String("persistent"),
			SpotPrice:                    &d.SpotPrice,
		}
		if d.BlockDurationMinutes != 0 {
			req.BlockDurationMinutes = &d.BlockDurationMinutes
		}
		spotInstanceRequest, err := d.getEC2Client().RequestSpotInstances(&req)
		if err != nil {
			return fmt.Errorf("Error request spot instance: %s", err)
		}
		d.SpotInstanceRequestId = *spotInstanceRequest.SpotInstanceRequests[0].SpotInstanceRequestId

		log.Info("Waiting for spot instance...")
		for i := 0; i < 3; i++ {
			// AWS eventual consistency means we could not have SpotInstanceRequest ready yet
			err = d.getEC2Client().WaitUntilSpotInstanceRequestFulfilled(&ec2.DescribeSpotInstanceRequestsInput{
				SpotInstanceRequestIds: []*string{&d.SpotInstanceRequestId},
			})
			if err != nil {
				if awsErr, ok := err.(awserr.Error); ok {
					if awsErr.Code() == spotInstanceRequestNotFoundCode {
						time.Sleep(5 * time.Second)
						continue
					}
				}
				return fmt.Errorf("Error fulfilling spot request: %v", err)
			}
			break
		}
		log.Infof("Created spot instance request %v", d.SpotInstanceRequestId)
		// resolve instance id
		for i := 0; i < 3; i++ {
			// Even though the waiter succeeded, eventual consistency means we could
			// get a describe output that does not include this information. Try a
			// few times just in case
			var resolvedSpotInstance *ec2.DescribeSpotInstanceRequestsOutput
			resolvedSpotInstance, err = d.getEC2Client().DescribeSpotInstanceRequests(&ec2.DescribeSpotInstanceRequestsInput{
				SpotInstanceRequestIds: []*string{&d.SpotInstanceRequestId},
			})
			if err != nil {
				// Unexpected; no need to retry
				return fmt.Errorf("Error describing previously made spot instance request: %v", err)
			}
			maybeInstanceId := resolvedSpotInstance.SpotInstanceRequests[0].InstanceId
			if maybeInstanceId != nil {
				var instances *ec2.DescribeInstancesOutput
				instances, err = d.getEC2Client().DescribeInstances(&ec2.DescribeInstancesInput{
					InstanceIds: []*string{maybeInstanceId},
				})
				if err != nil {
					// Retry if we get an id from spot instance but EC2 doesn't recognize it yet; see above, eventual consistency possible
					continue
				}
				instance = instances.Reservations[0].Instances[0]
				err = nil
				break
			}
			time.Sleep(5 * time.Second)
		}

		if err != nil {
			return fmt.Errorf("Error resolving spot instance to real instance: %v", err)
		}
	} else {
		inst, err := d.getEC2Client().RunInstances(&ec2.RunInstancesInput{
			ImageId:           &d.AMI,
			MinCount:          aws.Int64(1),
			MaxCount:          aws.Int64(1),
			KeyName:           &d.KeyName,
			InstanceType:      &d.InstanceType,
			NetworkInterfaces: netSpecs,
			Monitoring:        &ec2.RunInstancesMonitoringEnabled{Enabled: aws.Bool(d.Monitoring)},
			IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
				Name: &d.IamInstanceProfile,
			},
			BlockDeviceMappings: []*ec2.BlockDeviceMapping{bdm},
			UserData:            &userdata,
		})

		if err != nil {
			return fmt.Errorf("Error launching instance: %s", err)
		}
		instance = inst.Instances[0]
	}
	// Do this first so we can start bookkeeping
	d.InstanceId = *instance.InstanceId

	log.Debug("Settings tags for instance")
	err := d.configureTags(d.Tags)
	if err != nil {
		return fmt.Errorf("Unable to tag instance %s: %s", d.InstanceId, err)
	}

	d.waitForInstance()

	// TODO: RequestSpotLaunchSpecification doesn't support any kind of MetadataOptions block so instead of having
	//    two different ways to do this, we can just have 1.
	_, err = d.getEC2Client().ModifyInstanceMetadataOptions(&ec2.ModifyInstanceMetadataOptionsInput{
		HttpEndpoint:            aws.String("enabled"),
		HttpPutResponseHopLimit: aws.Int64(2),
		HttpTokens:              aws.String("optional"),
		InstanceId:              instance.InstanceId,
	})
	if err != nil {
		return err
	}

	log.Debug("waiting for ip address to become available")
	if err := mcnutils.WaitFor(d.instanceIpAvailable); err != nil {
		return err
	}

	if instance.PrivateIpAddress != nil {
		d.PrivateIPAddress = *instance.PrivateIpAddress
	}

	log.Debugf("created instance ID %s, IP address %s, Private IP address %s",
		d.InstanceId,
		d.IPAddress,
		d.PrivateIPAddress,
	)

	return nil
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, strconv.Itoa(dockerPort))), nil
}

func (d *Driver) GetIP() (string, error) {
	if d.runningIP != "" {
		return d.runningIP, nil
	}

	inst, err := d.getInstance()
	if err != nil {
		return "", err
	}

	if d.UsePublicIp {
		if inst.PublicIpAddress == nil {
			return "", fmt.Errorf("No public IP for instance %v", *inst.InstanceId)
		}
		d.runningIP = *inst.PublicIpAddress
		return *inst.PublicIpAddress, nil
	}

	if inst.PrivateIpAddress == nil {
		return "", fmt.Errorf("No IP for instance %v", *inst.InstanceId)
	}
	d.runningIP = *inst.PrivateIpAddress
	return *inst.PrivateIpAddress, nil
}

func (d *Driver) GetState() (state.State, error) {
	inst, err := d.getInstance()
	if err != nil {
		return state.Error, err
	}
	switch *inst.State.Name {
	case ec2.InstanceStateNamePending:
		return state.Starting, nil
	case ec2.InstanceStateNameRunning:
		return state.Running, nil
	case ec2.InstanceStateNameStopping:
		return state.Stopping, nil
	case ec2.InstanceStateNameShuttingDown:
		return state.Stopping, nil
	case ec2.InstanceStateNameStopped:
		return state.Stopped, nil
	case ec2.InstanceStateNameTerminated:
		return state.Error, nil
	default:
		log.Warnf("unrecognized instance state: %v", *inst.State.Name)
		return state.Error, nil
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	// TODO: use @nathanleclaire retry func here (ehazlett)
	return d.GetIP()
}

func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = defaultSSHPort
	}

	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = defaultSSHUser
	}

	return d.SSHUser
}

func (d *Driver) Start() error {
	_, err := d.getEC2Client().StartInstances(&ec2.StartInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})
	if err != nil {
		return err
	}

	return d.waitForInstance()
}

func (d *Driver) Stop() error {
	_, err := d.getEC2Client().StopInstances(&ec2.StopInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
		Force:       aws.Bool(false),
	})
	return err
}

func (d *Driver) Restart() error {
	_, err := d.getEC2Client().RebootInstances(&ec2.RebootInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})
	return err
}

func (d *Driver) Kill() error {
	_, err := d.getEC2Client().StopInstances(&ec2.StopInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
		Force:       aws.Bool(true),
	})
	return err
}

func (d *Driver) Remove() error {
	multierr := mcnutils.MultiError{
		Errs: []error{},
	}

	// In case of failure waiting for a SpotInstance, we must cancel the unfulfilled request, otherwise an instance may be created later.
	// If the instance was created, terminating it will be enough for canceling the SpotInstanceRequest
	if d.SpotInstanceRequestId != "" {
		if err := d.cancelSpotInstanceRequest(); err != nil {
			multierr.Errs = append(multierr.Errs, err)
		}
	}

	if err := d.terminate(); err != nil {
		multierr.Errs = append(multierr.Errs, err)
	}

	if err := d.deleteKeyPair(); err != nil {
		multierr.Errs = append(multierr.Errs, err)
	}

	if len(multierr.Errs) == 0 {
		return nil
	}

	return multierr
}

func (d *Driver) cancelSpotInstanceRequest() error {
	// NB: Canceling a Spot instance request does not terminate running Spot instances associated with the request
	_, err := d.getEC2Client().CancelSpotInstanceRequests(&ec2.CancelSpotInstanceRequestsInput{
		SpotInstanceRequestIds: []*string{&d.SpotInstanceRequestId},
	})
	return err
}

func (d *Driver) getInstance() (*ec2.Instance, error) {
	if d.InstanceId == "" {
		return nil, fmt.Errorf("no stored InstanceId, you should rm this instance")
	}
	instances, err := d.getEC2Client().DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})
	if err != nil {
		return nil, err
	}
	return instances.Reservations[0].Instances[0], nil
}

func (d *Driver) instanceIsRunning() bool {
	st, err := d.GetState()
	if err != nil {
		log.Debug(err)
	}
	if st == state.Running {
		return true
	}
	return false
}

func (d *Driver) waitForInstance() error {
	if err := mcnutils.WaitFor(d.instanceIsRunning); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createKeyPair() error {
	key, err := d.getEC2Client().DescribeKeyPairs(&ec2.DescribeKeyPairsInput{
		KeyNames: []*string{&d.KeyName},
	})

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == keypairNotFoundCode {
				log.Infof("found no key with name %s", d.KeyName)
			}
		} else {
			return err
		}
	}

	// In case we got a result with an empty set of keys
	if err == nil && len(key.KeyPairs) > 0 {
		d.AWSKeyID = *key.KeyPairs[0].KeyPairId
		log.Infof("already found key %s %s in AWS, so skipping key creation", d.KeyName, d.AWSKeyID)
		d.foundKeyWhileCreate = true
	}

	if d.SSHPrivateKeyPath == "" {
		return fmt.Errorf("you need to set --amazonec2-ssh-keypath")
	}

	log.Infof("Using SSHPrivateKeyPath: %s", d.SSHPrivateKeyPath)

	info, err := os.Stat(d.SSHPrivateKeyPath)
	if os.IsNotExist(err) {
		if err == nil && info.IsDir() {
			return fmt.Errorf("path (%s) is a directory, we want a file", d.SSHPrivateKeyPath)
		}
		if d.foundKeyWhileCreate {
			return fmt.Errorf("ssh key (%s) doesn't exist, yet a key with name (%s) is already uploaded to AWS, you probably need to delete the keypair in AWS so that I can auto-manage your key for you", d.SSHPrivateKeyPath, d.KeyName)
		} else {
			if err := ssh.GenerateSSHKey(d.SSHPrivateKeyPath); err != nil {
				return err
			}
		}
	}

	d.SSHKeyPath = d.SSHPrivateKeyPath
	pubKeyPath := d.SSHPrivateKeyPath + ".pub"
	log.Infof("pub key path: %s", pubKeyPath)
	publicKey, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	if !d.foundKeyWhileCreate {
		log.Infof("using this key material: %s", string(publicKey))
		log.Infof("creating key pair: %s", d.KeyName)
		info, err := d.getEC2Client().ImportKeyPair(&ec2.ImportKeyPairInput{
			KeyName:           &d.KeyName,
			PublicKeyMaterial: publicKey,
		})
		if err != nil {
			return err
		}
		d.AWSKeyID = *info.KeyPairId
	}

	return nil
}

func (d *Driver) terminate() error {
	if d.InstanceId == "" {
		log.Warn("Missing instance ID, this is likely due to a failure during machine creation")
		return nil
	}

	_, err := d.getEC2Client().TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})

	if err != nil {
		if strings.HasPrefix(err.Error(), "unknown instance") ||
			strings.HasPrefix(err.Error(), "InvalidInstanceID.NotFound") {
			log.Warn("Remote instance does not exist, proceeding with removing local reference")
			return nil
		}

		return fmt.Errorf("unable to terminate instance: %s", err)
	}
	return nil
}

func (d *Driver) isSwarmMaster() bool {
	return d.SwarmMaster
}

func (d *Driver) securityGroupAvailableFunc(id string) func() bool {
	return func() bool {

		securityGroup, err := d.getEC2Client().DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{&id},
		})
		if err == nil && len(securityGroup.SecurityGroups) > 0 {
			return true
		} else if err == nil {
			log.Debugf("No security group with id %v found", id)
			return false
		}
		log.Debug(err)
		return false
	}
}

func (d *Driver) configureTags(tagGroups string) error {

	tags := []*ec2.Tag{}
	tags = append(tags, &ec2.Tag{
		Key:   aws.String("Name"),
		Value: &d.MachineName,
	})

	if tagGroups != "" {
		t := strings.Split(tagGroups, ",")
		if len(t) > 0 && len(t)%2 != 0 {
			log.Warnf("Tags are not key value in pairs. %d elements found", len(t))
		}
		for i := 0; i < len(t)-1; i += 2 {
			tags = append(tags, &ec2.Tag{
				Key:   &t[i],
				Value: &t[i+1],
			})
		}
	}
	resources := []*string{&d.InstanceId}

	if d.SpotInstanceRequestId != "" {
		resources = append(resources, aws.String(d.SpotInstanceRequestId))
	}
	_, err := d.getEC2Client().CreateTags(&ec2.CreateTagsInput{
		Resources: resources,
		Tags:      tags,
	})

	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) configureSecurityGroups(groupNames []string) error {
	if len(groupNames) == 0 {
		log.Debugf("no security groups to configure in %s", d.VpcId)
		return nil
	}

	log.Debugf("configuring security groups in %s", d.VpcId)

	filters := []*ec2.Filter{
		{
			Name:   aws.String("group-name"),
			Values: makePointerSlice(groupNames),
		},
		{
			Name:   aws.String("vpc-id"),
			Values: []*string{&d.VpcId},
		},
	}
	groups, err := d.getEC2Client().DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: filters,
	})
	if err != nil {
		return err
	}

	var groupsByName = make(map[string]*ec2.SecurityGroup)
	for _, securityGroup := range groups.SecurityGroups {
		groupsByName[*securityGroup.GroupName] = securityGroup
	}

	for _, groupName := range groupNames {
		var group *ec2.SecurityGroup
		securityGroup, ok := groupsByName[groupName]
		if ok {
			log.Debugf("found existing security group (%s) in %s", groupName, d.VpcId)
			group = securityGroup
		} else {
			log.Debugf("creating security group (%s) in %s", groupName, d.VpcId)
			groupResp, err := d.getEC2Client().CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
				GroupName:   aws.String(groupName),
				Description: aws.String("Docker Machine"),
				VpcId:       aws.String(d.VpcId),
			})
			if err != nil {
				return err
			}
			// Manually translate into the security group construct
			group = &ec2.SecurityGroup{
				GroupId:   groupResp.GroupId,
				VpcId:     aws.String(d.VpcId),
				GroupName: aws.String(groupName),
			}
			// wait until created (dat eventual consistency)
			log.Debugf("waiting for group (%s) to become available", *group.GroupId)
			if err := mcnutils.WaitFor(d.securityGroupAvailableFunc(*group.GroupId)); err != nil {
				return err
			}
		}
		d.SecurityGroupIds = append(d.SecurityGroupIds, *group.GroupId)

		perms, err := d.configureSecurityGroupPermissions(group)
		if err != nil {
			return err
		}

		if len(perms) != 0 {
			log.Debugf("authorizing group %s with permissions: %v", groupNames, perms)
			_, err := d.getEC2Client().AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				GroupId:       group.GroupId,
				IpPermissions: perms,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *Driver) configureSecurityGroupPermissions(group *ec2.SecurityGroup) ([]*ec2.IpPermission, error) {
	if !d.SecurityGroupManage {
		log.Debug("Skipping permission configuration on security groups")
		return nil, nil
	}
	hasPorts := make(map[string]bool)
	for _, p := range group.IpPermissions {
		if p.FromPort != nil {
			hasPorts[fmt.Sprintf("%d/%s", *p.FromPort, *p.IpProtocol)] = true
		}
	}

	perms := []*ec2.IpPermission{}

	if !hasPorts[fmt.Sprintf("%d/tcp", d.BaseDriver.SSHPort)] {
		perms = append(perms, &ec2.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(int64(d.BaseDriver.SSHPort)),
			ToPort:     aws.Int64(int64(d.BaseDriver.SSHPort)),
			IpRanges:   []*ec2.IpRange{{CidrIp: aws.String(ipRange)}},
		})
	}

	if !hasPorts[fmt.Sprintf("%d/tcp", dockerPort)] {
		perms = append(perms, &ec2.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(int64(dockerPort)),
			ToPort:     aws.Int64(int64(dockerPort)),
			IpRanges:   []*ec2.IpRange{{CidrIp: aws.String(ipRange)}},
		})
	}

	if !hasPorts[fmt.Sprintf("%d/tcp", swarmPort)] && d.SwarmMaster {
		perms = append(perms, &ec2.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(int64(swarmPort)),
			ToPort:     aws.Int64(int64(swarmPort)),
			IpRanges:   []*ec2.IpRange{{CidrIp: aws.String(ipRange)}},
		})
	}

	for _, p := range d.OpenPorts {
		port, protocol := driverutil.SplitPortProto(p)
		portNum, err := strconv.ParseInt(port, 10, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid port number %s: %s", port, err)
		}
		if !hasPorts[fmt.Sprintf("%s/%s", port, protocol)] {
			perms = append(perms, &ec2.IpPermission{
				IpProtocol: aws.String(protocol),
				FromPort:   aws.Int64(portNum),
				ToPort:     aws.Int64(portNum),
				IpRanges:   []*ec2.IpRange{{CidrIp: aws.String(ipRange)}},
			})
		}
	}

	log.Debugf("configuring security group authorization for %s", ipRange)

	return perms, nil
}

func (d *Driver) deleteKeyPair() error {
	if d.KeyName == "" {
		log.Warn("Missing key pair name, this is likely due to a failure during machine creation")
		return nil
	}

	instanceList, err := d.getEC2Client().DescribeInstances(&ec2.DescribeInstancesInput{
		DryRun: nil,
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: aws.StringSlice([]string{"running", "stopped"}),
			},
			{
				Name:   aws.String("key-name"),
				Values: aws.StringSlice([]string{d.KeyName}),
			},
		},
	})

	if err != nil {
		return err
	}

	if len(instanceList.Reservations) > 0 {
		log.Info("skipping key delete because there are still instances referencing this key")
		return nil
	}

	if d.foundKeyWhileCreate {
		log.Info("we found this key while doing a create, but we've thrown an error, so don't actually delete because we probably didn't make it")
		return nil
	}

	if d.InstanceId == "" {
		log.Info("Missing instance ID, to prevent accidental deletes, we're skipping keypair delete")
		return nil
	}

	log.Debugf("deleting key pair: %s", d.KeyName)

	_, err = d.getEC2Client().DeleteKeyPair(&ec2.DeleteKeyPairInput{
		KeyName: &d.KeyName,
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) getDefaultVPCId() (string, error) {
	output, err := d.getEC2Client().DescribeAccountAttributes(&ec2.DescribeAccountAttributesInput{})
	if err != nil {
		return "", err
	}

	for _, attribute := range output.AccountAttributes {
		if *attribute.AttributeName == "default-vpc" {
			value := *attribute.AttributeValues[0].AttributeValue
			if value == "none" {
				return "", errors.New("default-vpc is 'none'")
			}
			return value, nil
		}
	}

	return "", errors.New("No default-vpc attribute")
}

func generateId() string {
	rb := make([]byte, 10)
	_, err := rand.Read(rb)
	if err != nil {
		log.Warnf("Unable to generate id: %s", err)
	}

	h := md5.New()
	io.WriteString(h, string(rb))
	return fmt.Sprintf("%x", h.Sum(nil))
}
