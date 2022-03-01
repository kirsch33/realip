package realip

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

type AwsIPRanges struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix           string `json:"ip_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"prefixes"`
}

func LoadCloudFront() ([]*net.IPNet, error) {
	set := make([]*net.IPNet, 0)

	awsRanges, err := loadAwsIPRanges()
	if err != nil {
		return set, err
	}

	for i := 0; i < len(awsRanges.Prefixes); i++ {
		if awsRanges.Prefixes[i].Service == "CLOUDFRONT" {
			_, ipnet, err := net.ParseCIDR(awsRanges.Prefixes[i].IPPrefix)
			if err != nil {
				// ok to return a partial set as this will not be used if an error is returned
				return set, err
			}
			set = append(set, ipnet)
		}
	}

	return set, nil
}

func loadAwsIPRanges() (AwsIPRanges, error) {
	var awsRanges AwsIPRanges

	resp, err := http.DefaultClient.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return AwsIPRanges{}, err
	}

	err = json.NewDecoder(resp.Body).Decode(&awsRanges)
	if err != nil {
		return AwsIPRanges{}, err
	}
	return awsRanges, nil
}

// help for updating the preset range
func printRange() {

	awsRanges, err := loadAwsIPRanges()
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(awsRanges.Prefixes); i++ {
		if awsRanges.Prefixes[i].Service == "CLOUDFRONT" {
			fmt.Printf("MustParseCIDR(\"%s\"),\n", awsRanges.Prefixes[i].IPPrefix)
		}
	}
}
