#!/bin/bash

read -p "Enter CVE: " cve

response=$(curl -s "https://poc-in-github.motikan2010.net/api/v1/?cve_id=$cve")
html_urls=$(echo "$response" | jq -r '.pocs[].html_url')
if [ -z "$html_urls" ] || [ "$html_urls" == "null" ]; then
  echo -e "POC $cve URL not found in poc-in-github\n"
else
  echo -e "$cve URLs:"
  echo -e "$html_urls"
fi

exploits_dir="Exploits"

# Check if the Exploits directory exists, and create it if it doesn't
if [ ! -d "$exploits_dir" ]; then
  echo -e "Creating $exploits_dir directory...\n"
  mkdir "$exploits_dir"
fi

for url in $html_urls; do
  repo_name=$(echo "$url" | awk -F/ '{print $4}')
  clone_dir="$exploits_dir/$repo_name-${cve}"

  if [ -d "$clone_dir" ]; then
    echo "Directory $clone_dir already exists. Skipping..."
  else
    echo -e "Cloning $url into $clone_dir\n"
    git clone "$url" "$clone_dir"
  fi
done
