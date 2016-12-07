source subcommands/fw_common.sh

## <Rules>
# Reject
fw_rule filter +reject any any -p tcp -j REJECT --reject-with tcp-reset
fw_rule filter +reject any any -j REJECT
fw_rule filter +reject any any -j DROP

# Log Drop
fw_rule filter +log_drop any any -m limit --limit 1/sec -j LOG --log-prefix "LD: "
fw_rule filter +log_drop any any -j DROP

# Log Reject
fw_rule filter +log_reject any any -m limit --limit 1/sec -j LOG --log-prefix "LR: "
fw_rule filter +log_reject any any -j +reject

## </Rules>
