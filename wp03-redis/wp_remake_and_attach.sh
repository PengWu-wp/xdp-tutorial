
IFNAME=ens40
XDPMODE=-S
# another mode is -N

if [[ $1x = -Ux ]]; then
	./xdp_pass_user -d $IFNAME $XDPMODE -U
	echo "Program detached from $IFNAME"
	exit 0
fi



make

./xdp_pass_user -d $IFNAME $XDPMODE -U
./xdp_pass_user -d $IFNAME $XDPMODE


