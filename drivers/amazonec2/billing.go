package amazonec2

import (
	"encoding/json"
	"time"
)

type ProductOffer struct {
	Product         Product   `json:"product"`
	Terms           Terms     `json:"terms"`
	PublicationDate time.Time `json:"publicationDate"`
	ServiceCode     string    `json:"serviceCode"`
}

type Product struct {
	Attributes    map[string]string `json:"attributes"`
	ProductFamily string            `json:"productFamily"`
	Sku           string            `json:"sku"`
}

type Terms struct {
	Reserved []Offer
	OnDemand []Offer
}

func (ts *Terms) UnmarshalJSON(data []byte) error {
	var genericMap map[string]map[string]Offer
	err := json.Unmarshal(data, &genericMap)
	if err != nil {
		return err
	}
	if _, ok := genericMap["OnDemand"]; ok {
		for _, v := range genericMap["OnDemand"] {
			ts.OnDemand = append(ts.OnDemand, v)
		}
	}
	if _, ok := genericMap["Reserved"]; ok {
		for _, v := range genericMap["Reserved"] {
			ts.Reserved = append(ts.Reserved, v)
		}
	}
	return nil
}

type Offer struct {
	EffectiveDate   time.Time      `json:"effectiveDate"`
	OfferTermCode   string         `json:"offerTermCodes"`
	PriceDimensions []Dimension    `json:"priceDimensions"`
	Sku             string         `json:"sku"`
	TermAttributes  TermAttributes `json:"termAttributes"`
}

func (o *Offer) UnmarshalJSON(data []byte) error {
	genericMap := make(map[string]interface{})

	err := json.Unmarshal(data, &genericMap)
	if err != nil {
		return err
	}
	for k, v := range genericMap {
		switch k {
		case "effectiveDate":
			t, err := time.Parse(time.RFC3339, v.(string))
			if err != nil {
				return err
			}
			o.EffectiveDate = t
		case "offerTermCodes":
			o.OfferTermCode = v.(string)
		case "sku":
			o.Sku = v.(string)
		case "termAttributes":
			var t TermAttributes
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			err = json.Unmarshal(b, &t)
			if err != nil {
				return err
			}
			o.TermAttributes = t
		case "priceDimensions":
			var dimensionMap map[string]Dimension
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			err = json.Unmarshal(b, &dimensionMap)
			if err != nil {
				return err
			}
			for _, v := range dimensionMap {
				o.PriceDimensions = append(o.PriceDimensions, v)
			}
		}
	}
	return nil
}

type TermAttributes struct {
	LeaseContractLength string `json:"LeaseContractLength"`
	OfferingClass       string `json:"OfferingClass"`
	PurchaseOption      string `json:"PurchaseOption"`
}

type Dimension struct {
	Description  string       `json:"description"`
	PricePerUnit PricePerUnit `json:"pricePerUnit"`
	RateCode     string       `json:"rateCode"`
	Unit         string       `json:"unit"`
}

type PricePerUnit struct {
	USD string `json:"USD"`
}
