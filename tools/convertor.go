package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type WFRecord struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	CVE   string `json:"cve"`
	CVSS  struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Software []struct {
		Type             string `json:"type"`
		Slug             string `json:"slug"`
		AffectedVersions map[string]struct {
			FromVersion   string `json:"from_version"`
			FromInclusive bool   `json:"from_inclusive"`
			ToVersion     string `json:"to_version"`
			ToInclusive   bool   `json:"to_inclusive"`
		} `json:"affected_versions"`
	} `json:"software"`
	References []string `json:"references"`
}

type VulnEntry struct {
	ID            string  `json:"id"`
	CVSS          float64 `json:"cvss"`
	Title         string  `json:"title"`
	From          string  `json:"from"`
	FromInclusive bool    `json:"from_inclusive"`
	To            string  `json:"to"`
	ToInclusive   bool    `json:"to_inclusive"`
	Patched       string  `json:"patched"`
}

type VulnDB map[string][]VulnEntry

func extractCVE(rec WFRecord) string {
	if rec.CVE != "" {
		return strings.ToUpper(rec.CVE)
	}
	re := regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
	if m := re.FindString(rec.Title); m != "" {
		return strings.ToUpper(m)
	}
	for _, u := range rec.References {
		if m := re.FindString(u); m != "" {
			return strings.ToUpper(m)
		}
	}
	return "WF-" + rec.ID
}

func main() {
	f, err := os.Open("wordfence_production.json")
	if err != nil {
		fmt.Println("[-] Cannot open wordfence_production.json:", err)
		os.Exit(1)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	t, err := decoder.Token()
	if err != nil {
		os.Exit(1)
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		fmt.Println("[-] Expected top-level object.")
		os.Exit(1)
	}

	db := make(VulnDB)
	records := 0

	for decoder.More() {
		_, _ = decoder.Token()

		var rec WFRecord
		if err := decoder.Decode(&rec); err != nil {
			continue
		}
		records++

		cve := extractCVE(rec)

		for _, sw := range rec.Software {
			if sw.Slug == "" {
				continue
			}
			for _, rd := range sw.AffectedVersions {
				from := rd.FromVersion
				to := rd.ToVersion
				if from == "" {
					from = "*"
				}
				if to == "" {
					to = "*"
				}
				entry := VulnEntry{
					ID:            cve,
					CVSS:          rec.CVSS.Score,
					Title:         rec.Title,
					From:          from,
					FromInclusive: rd.FromInclusive,
					To:            to,
					ToInclusive:   rd.ToInclusive,
					Patched:       "", // optional; fill from patched_versions if desired
				}
				dup := false
				for _, x := range db[sw.Slug] {
					if x.ID == entry.ID && x.From == entry.From && x.To == entry.To {
						dup = true
						break
					}
				}
				if !dup {
					db[sw.Slug] = append(db[sw.Slug], entry)
				}
			}
		}
	}

	fmt.Printf("[+] Parsed %d records -> %d plugins\n", records, len(db))

	out, _ := os.Create("vuln_db.json")
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.Encode(db)
	fmt.Println("[+] Wrote vuln_db.json")
}
