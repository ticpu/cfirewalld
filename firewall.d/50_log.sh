source subcommands/fw_common.sh

## <Rules>
# Log No Match
fw_rule filter forward any any -j LOG --log-prefix "NM: "
## </Rules>
