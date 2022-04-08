package realip

import (
	"bufio"
	"net"
	"net/http"
)

func LoadCloudflare() ([]*net.IPNet, error) {
	set := make([]*net.IPNet, 0)

	loaded, err := loadList("https://www.cloudflare.com/ips-v4")
	if err != nil {
		return set, err
	}

	set = append(set, loaded...)

	loaded, err = loadList("https://www.cloudflare.com/ips-v6")
	if err != nil {
		return set, err
	}

	set = append(set, loaded...)

	return set, nil
}

func loadList(url string) ([]*net.IPNet, error) {
	set := make([]*net.IPNet, 0)

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return set, err
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		_, ipnet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return set, err
		}
		set = append(set, ipnet)
	}

	return set, nil
}
