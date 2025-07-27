#!/usr/bin/env bash
# Copyright 2022 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail
apt update && apt -y install jq
wget -q -O /usr/local/bin/snyk https://static.snyk.io/cli/latest/snyk-linux && chmod +x /usr/local/bin/snyk
mkdir -p "${ARTIFACTS}"
if [ -z "${SNYK_TOKEN}" ]; then
    echo "SNYK_TOKEN env var is not set, required for snyk scan"
    exit 1
fi
echo "Running snyk scan .."
EXIT_CODE=0
DEBUG_LOG_FILE=$(mktemp)
RESULT_UNFILTERED=$(snyk test -d --json 2> "$DEBUG_LOG_FILE") || EXIT_CODE=$?
if [ $EXIT_CODE -gt 1 ]; then
    echo "Failed to run snyk scan with exit code $EXIT_CODE"
    cat "$DEBUG_LOG_FILE"
    exit 1
fi
rm -f "$DEBUG_LOG_FILE"

RESULT=$(echo $RESULT_UNFILTERED | jq \
'{vulnerabilities: .vulnerabilities | map(select((.type != "license") and (.version !=  "0.0.0"))) | select(length > 0) }')
if [[ ${RESULT} ]]; then
    CVE_IDs=$(echo $RESULT | jq '.vulnerabilities[].identifiers.CVE | unique[]' | sort -u)
    #convert string to array
    CVE_IDs_array=(`echo ${CVE_IDs}`)
    #TODO:Implement deduplication of CVE IDs in future
    for i in "${CVE_IDs_array[@]}"
    do
        if [[ "$i" == *"CVE"* ]]; then
            #Look for presence of GitHub Issues for detected CVEs. If no issues are present, this CVE needs triage
            #Once the job fails, CVE is triaged by SIG Security and a tracking issue is created.
            #This will allow in the next run for the job to pass again
            TOTAL_COUNT=$(curl -H "Accept: application/vnd.github.v3+json" "https://api.github.com/search/issues?q=repo:kubernetes/kubernetes+${i}" | jq .total_count)
            if [[ $TOTAL_COUNT -eq 0 ]]; then
            echo "Vulnerability filtering failed"
            exit 1
            fi
        fi
    done
fi
echo "Build time dependency scan completed"

# container images scan
echo "Fetch the list of k8s images"
curl -Ls https://sbom.k8s.io/$(curl -Ls https://dl.k8s.io/release/latest.txt)/release | grep "SPDXID: SPDXRef-Package-registry.k8s.io" | grep -v sha256 | cut -d- -f3- | sed 's/-/\//' | sed 's/-v1/:v1/' > images
while read image; do
    echo "Running container image scan for $image"
    EXIT_CODE=0
    DEBUG_LOG_FILE=$(mktemp)
    RESULT_UNFILTERED=$(snyk container test $image -d --json 2> "$DEBUG_LOG_FILE") || EXIT_CODE=$?
    if [ $EXIT_CODE -gt 1 ]; then
        echo "Failed to run snyk scan with exit code $EXIT_CODE"
        cat "$DEBUG_LOG_FILE"
        exit 1
    fi
    rm -f "$DEBUG_LOG_FILE"

    RESULT=$(echo $RESULT_UNFILTERED | jq \
    '{vulnerabilities: .vulnerabilities | map(select(.isUpgradable == true or .isPatchable == true)) | select(length > 0) }')
    if [[ ${RESULT} ]]; then
        echo "Vulnerability filtering failed"
        # exit 1 (To allow other images to be scanned even if one fails)
    else
        echo "Scan completed image $image"
    fi
done < images