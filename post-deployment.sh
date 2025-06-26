subscriptionId="id"
resourceGroup="rg"
logicAppName="healthcheck"

az rest --method post --url "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups/$resourceGroup/providers/Microsoft.Logic/workflows/$logicAppName/triggers/Timer_Trigger/run?api-version=2016-10-01"

sleep 5
response=$(az rest --method get --url \
  "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Logic/workflows/$logicAppName/runs?api-version=2019-05-01&$top=1")

# Extract the most recent run ID (the 'status' property of the most recent run)
run=$(echo "$response" | jq -r '.value[0].properties.status')

echo "Most recent run ID: $run"

if [ "$run" = "Succeeded" ]; then
  echo "Logic App run succeeded."
elif [ "$run" = "Failed" ]; then
  echo "Logic App run failed."
  exit 1
else
  echo "Logic App run status: $run"
fi
