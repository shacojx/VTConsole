package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
)

const (
	apikey         = "bcac2682cdd83c3e339329b61520377cecbd1d3c5435cea888f568a8df14a983"
	virustotalLink = "http://www.virustotal.com/vtapi/v2"
)

type Status struct {
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

type ScanResponse struct {
	Status

	ScanId    string `json:"scan_id"`
	Sha1      string `json:"sha1"`
	Resource  string `json:"resource"`
	Sha256    string `json:"sha256"`
	Permalink string `json:"permalink"`
	Md5       string `json:"md5"`
}

type ScanUrlResponse struct {
	Status

	ScanId    string `json:"scan_id"`
	link      string `json:"url"`
	Resource  string `json:"resource"`
	Scandate  string `json:"scan_date"`
	Permalink string `json:"permalink"`
}

type FileScan struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

type ReportResponse struct {
	Status
	Resource  string              `json:"resource"`
	ScanId    string              `json:"scan_id"`
	Sha1      string              `json:"sha1"`
	Sha256    string              `json:"sha256"`
	Md5       string              `json:"md5"`
	Scandate  string              `json:"scan_date"`
	Positives int                 `json:"positives"`
	Total     int                 `json:"total"`
	Permalink string              `json:"permalink"`
	Scans     map[string]FileScan `json:"scans"`
}

type DetectedUrl struct {
	ScanDate  string `json:"scan_date"`
	Url       string `json:"url"`
	Positives int    `json:"positives"`
	Total     int    `json:"total"`
}

type Resolution struct {
	LastResolved string `json:"last_resolved"`
	Hostname     string `json:"hostname"`
}

type DomainResolution struct {
	LastResolved string `json:"last_resolved"`
	IpAddress    string `json:"ip_address"`
}

type IpAddressReportResponse struct {
	Status
	ASN          int           `json:"ASN"`
	Owner        string        `json:"as_owner"`
	Country      string        `json:"country"`
	Resolutions  []Resolution  `json:"resolutions"`
	DetectedUrls []DetectedUrl `json:"detected_urls"`
}

type DomainReportResponse struct {
	Status
	Forcepoint  string             `json:"Forcepoint ThreatSeeker category"`
	Category    string             `json:"sophos category"`
	Subdomains  []string           `json:"subdomains"`
	Resolutions []DomainResolution `json:"resolutions"`
}

func ScanFile(path string, file io.Reader) {
	params := map[string]string{
		"apikey": apikey,
	}

	request, err := newfileUploadRequest(virustotalLink+"/file/scan", params, path, file)

	if err != nil {
		panic(err)
	}

	client := &http.Client{}

	resp, err := client.Do(request)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var scanResponse = new(ScanResponse)
	err = json.Unmarshal(contents, &scanResponse)

	ReportFile(scanResponse.Resource, path)
}

func ScanUrl(url2 string) {
	u, err := url.Parse(virustotalLink + "/url/scan")

	params := url.Values{"apikey": {apikey}, "url": {url2}}

	resp, err := http.PostForm(u.String(), params)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	var scanUrlResponse = new(ScanUrlResponse)
	err = json.Unmarshal(contents, &scanUrlResponse)

	ReportUrl(scanUrlResponse.Resource, url2)
}

func ReportFile(resource string, path string) {
	data := url.Values{"apikey": {apikey}, "resource": {resource}}

	u, err := url.Parse(virustotalLink + "/file/report")
	u.RawQuery = data.Encode()

	res, err := http.Get(u.String())
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	var ReportResponse = new(ReportResponse)
	err = json.Unmarshal(body, &ReportResponse)
	if err != nil {
		panic(err)
	}

	data1 := []string{path, resource, ReportResponse.Md5, ReportResponse.Sha1, ReportResponse.Sha256, ReportResponse.Scandate}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Resource", "Md5", "Sha1", "Sha256", "Scan_date"})
	table.Append(data1)

	table.Render()

	table1 := tablewriter.NewWriter(os.Stdout)
	table1.SetHeader([]string{"Name AntiVirus", "Detected", "Version", "Result", "Update"})

	for key1, value := range ReportResponse.Scans {
		data2 := []string{key1, strconv.FormatBool(value.Detected), value.Version, value.Result, value.Update}
		table1.Append(data2)
	}
	table1.Render()
}

func ReportUrl(resource string, url2 string) {
	params := url.Values{"apikey": {apikey}, "resource": {resource}}

	u, err := url.Parse(virustotalLink + "/url/report")

	resp, err := http.PostForm(u.String(), params)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	var ReportResponse = new(ReportResponse)

	err = json.Unmarshal(contents, &ReportResponse)

	data1 := []string{url2, resource, ReportResponse.Md5, ReportResponse.Sha1, ReportResponse.Sha256, ReportResponse.Scandate, strconv.Itoa(ReportResponse.Total)}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Resource", "Md5", "Sha1", "Sha256", "Scan_date", "Total"})
	table.Append(data1)

	table.Render()

	table1 := tablewriter.NewWriter(os.Stdout)
	table1.SetHeader([]string{"Name AntiVirus", "Detected", "Version", "Result", "Update"})

	for key1, value := range ReportResponse.Scans {
		data2 := []string{key1, strconv.FormatBool(value.Detected), value.Version, value.Result, value.Update}
		table1.Append(data2)
	}
	table1.Render()
}

func DomainReport(domain string) {
	u, err := url.Parse(virustotalLink + "/domain/report")
	u.RawQuery = url.Values{"apikey": {apikey}, "domain": {domain}}.Encode()

	resp, err := http.Get(u.String())

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var domainReportResponse = new(DomainReportResponse)

	err = json.Unmarshal(contents, &domainReportResponse)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Category", "Forcepoint", "Last_resolved", "IpAddress"})

	for _, value := range domainReportResponse.Resolutions {
		data2 := []string{domain, domainReportResponse.Category, domainReportResponse.Forcepoint, value.LastResolved, value.IpAddress}
		table.Append(data2)
	}
	table.SetAutoMergeCells(true)
	table.Render()

	table2 := tablewriter.NewWriter(os.Stdout)
	table2.SetHeader([]string{"STT", "Subdomains"})

	for key, value := range domainReportResponse.Subdomains {
		data3 := []string{strconv.Itoa(key), value}
		table2.Append(data3)
	}
	table2.Render()

}

func IpAddressReport(ip string) {
	u, err := url.Parse(virustotalLink + "/ip-address/report")
	u.RawQuery = url.Values{"apikey": {apikey}, "ip": {ip}}.Encode()

	resp, err := http.Get(u.String())

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var ipAddressReportResponse = new(IpAddressReportResponse)

	err = json.Unmarshal(contents, &ipAddressReportResponse)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ASN", "ASN_Owner", "Country", "Last_resolved", "IpAddress"})
	for _, value := range ipAddressReportResponse.Resolutions {
		data1 := []string{strconv.Itoa(ipAddressReportResponse.ASN), ipAddressReportResponse.Owner, ipAddressReportResponse.Country, value.LastResolved, value.Hostname}
		table.Append(data1)
	}
	table.SetAutoMergeCells(true)
	table.Render()

	if len(ipAddressReportResponse.DetectedUrls) > 0 {
		table1 := tablewriter.NewWriter(os.Stdout)
		table1.SetHeader([]string{"Url", "Positives", "Total", "Scan_date"})
		for _, value := range ipAddressReportResponse.DetectedUrls {
			data2 := []string{value.Url, strconv.Itoa(value.Positives), strconv.Itoa(value.Total), value.ScanDate}
			table1.Append(data2)
		}
		table1.Render()
	}
}

func newfileUploadRequest(uri string, params map[string]string, path string, file io.Reader) (*http.Request, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for key, val := range params {
		_ = writer.WriteField(key, val)
	}

	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, file)

	err = writer.Close()

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, body)

	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, err
}

func Banner() {
	b := (``)
	b += "\n" + (``)
	b += "\n" + ("   ") + ("-----------------------------------------------------------------------------------------------------------------------------")
	b += "\n" + ("   ") + ("|    ********************                                                                                                   |")
	b += "\n" + ("   ") + ("|     *        V        *   *           * ***** ******** *      *  *****   *****    *****   *****      *       *            |")
	b += "\n" + ("   ") + ("|      *       N        *    *         *    *   *      * *      * *     *    *     *     *    *       * *      *            |")
	b += "\n" + ("   ") + ("|       *      C        *     *       *     *   *      * *      *  *         *     *     *    *      *   *     *            |")
	b += "\n" + ("   ") + ("|        *     E        *      *     *      *   *     *  *      *     *      *     *     *    *     *******    *            |")
	b += "\n" + ("   ") + ("|       *      R        *       *   *       *   *  *     *      *       *    *     *     *    *    *       *   *            |")
	b += "\n" + ("   ") + ("|      *       T        *        * *        *   *    *   *      * *     *    *     *     *    *   *         *  *            |")
	b += "\n" + ("   ") + ("|     * (The Inevitable)*         *       ***** *      *  ******   *****     *      *****     *  *           * *******      |")
	b += "\n" + ("   ") + ("|    ********************                                                                                                   |")
	b += "\n" + ("   ") + ("|                                                        CREATE BY NAT_CEIL                                                 |")
	b += "\n" + ("   ") + ("-----------------------------------------------------------------------------------------------------------------------------")
	b += "\n" + ("   ") + ("1. File")
	b += "\n" + ("   ") + ("2. Url")
	b += "\n" + ("   ") + ("3. Domain")
	b += "\n" + ("   ") + ("4. Ip Address")
	fmt.Println(b)
}

func main() {
	Banner()
	option1 := bufio.NewReader(os.Stdin)
	fmt.Print("  (***) Your option: ")
	option2, _ := option1.ReadString('\n')
	option2 = strings.Replace(option2, "\n", "", -1)
	option2 = strings.Replace(option2, "\r", "", -1)
	option, err := strconv.Atoi(option2)

	if err != nil {
		panic(err)
	}

	switch option {
	case 1:

		pathFile := bufio.NewReader(os.Stdin)
		fmt.Printf("  (***) Please give me path file to scan (C:/filename): ")
		path, _ := pathFile.ReadString('\n')
		path = strings.Replace(path, "\n", "", -1)
		path = strings.Replace(path, "\r", "", -1)
		file, err := os.Open(path)

		if err != nil {
			log.Fatal(err)
		}
		ScanFile(path, file)

	case 2:

		url := bufio.NewReader(os.Stdin)
		fmt.Printf("  (***) Please give me url to scan (vncert.gov.vn): ")
		urlScan, _ := url.ReadString('\n')
		urlScan = strings.Replace(urlScan, "\n", "", -1)
		urlScan = strings.Replace(urlScan, "\r", "", -1)
		ScanUrl(urlScan)

	case 3:

		domain := bufio.NewReader(os.Stdin)
		fmt.Printf("  (***) Please give me domain to scan (vncert.gov.vn): ")
		domainScan, _ := domain.ReadString('\n')
		domainScan = strings.Replace(domainScan, "\n", "", -1)
		domainScan = strings.Replace(domainScan, "\r", "", -1)
		DomainReport(domainScan)

	case 4:

		ip := bufio.NewReader(os.Stdin)
		fmt.Printf("  (***) Please give me url to scan (1.2.3.4): ")
		ipScan, _ := ip.ReadString('\n')
		ipScan = strings.Replace(ipScan, "\n", "", -1)
		ipScan = strings.Replace(ipScan, "\r", "", -1)
		IpAddressReport(ipScan)
	}
}
