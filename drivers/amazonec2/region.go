package amazonec2

import (
	"errors"
)

type region struct {
	AmiId string
}

var awsRegionsList = []string{
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-south-1",
	"ca-central-1",
	"cn-north-1",
	"cn-northwest-1",
	"eu-north-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"sa-east-1",
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"us-gov-west-1",
}

func validateAwsRegion(region string) (string, error) {
	for _, v := range awsRegionsList {
		if v == region {
			return region, nil
		}
	}

	return "", errors.New("Invalid region specified")
}
