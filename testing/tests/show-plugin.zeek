# @TEST-EXEC: zeek -NN OSS::PRES |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
