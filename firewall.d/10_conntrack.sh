source subcommands/fw_common.sh

## <Rules>
fw_rule filter forward any any -m state --state ESTABLISHED -j ACCEPT
## </Rules>
