#!/bin/bash

TESTMODE=PASS
INTF=eth1
MODE=-N


while getopts "m:hSNU" optname
do
    case "$optname" in
      "d")
	      INTF=$OPTARG
	      ;;
      "m")
	      TESTMODE=$OPTARG
	      ;;
      "h")
	      echo "eg:./wp_change.sh -m <PASS/DROP/TX> <-S/-N> <-U to unbind>"
	      exit 0
	      ;;
      "S")
	      MODE=-S
	      ;;
      "N")
	      MODE=-N
	      ;;
      "U")
	      ./xdp_test_user -d $INTF $MODE -U
              exit 0
	      ;;
      ":")
        echo "No argument value for option $OPTARG"
        ;;
      "?")
        echo "Unknown option $OPTARG"
        ;;
      *)
        echo "Unknown error while processing options"
        ;;
    esac
done

if [ $# -eq 0 ]
then
	echo "testmode not specified! eg:./wp_change.sh -m <PASS/DROP/TX> <-S/-N> <-U to unbind>"
	exit -1
fi

cp xdp_test_kern.c xdp_test_kern.c.bak

cat xdp_test_kern.c | sed "s/XDP_[A-Z]*/XDP_$TESTMODE/g" > temp.c
mv temp.c xdp_test_kern.c
cat xdp_test_user.c | sed "s/W:XDP_[A-Z]*/W:XDP_$TESTMODE/g" > temp.c
mv temp.c xdp_test_user.c
make
./xdp_test_user -d $INTF $MODE -U
./xdp_test_user -d $INTF $MODE






