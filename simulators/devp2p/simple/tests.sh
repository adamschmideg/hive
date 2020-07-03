#!/usr/bin/env bash


echo "Starting simulator."
cd /go/src/github.com/ethereum/hive/simulators/devp2p/simple/

echo "Simulator endpoint: $HIVE_SIMULATOR"
echo "Simulator parallelism: $HIVE_PARALLELISM"
echo "Simulator logfile: $HIVE_SIMLOG"

echo "{ \"hostURI\":\"$HIVE_SIMULATOR\" }" >hiveProviderConfig.json
 

if [ "${HIVE_DEBUG}" = true ]; then
    dlv test  	--headless  --listen=:2345 --log=true  --api-version=2 -simProvider="hive" -providerConfig="hiveProviderConfig.json"  -test.parallel "$HIVE_PARALLELISM" -test.v
else
   
    go test  -simProvider="hive" -providerConfig="hiveProviderConfig.json"  -test.parallel $HIVE_PARALLELISM  -test.v
fi

echo "Ending simulator."
