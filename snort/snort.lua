-- =============================================================================
-- Snort 3 configuration for the Cooperative Cloud IDS Framework.
-- Passive sniffing mode. Consumes the shared Emerging Threats Open ruleset
-- mounted at /etc/snort/rules and writes compact alerts to snort.log.
-- =============================================================================

-- Home network = the emulated cloud bridge subnet.
HOME_NET = '172.20.0.0/16'
EXTERNAL_NET = '!172.20.0.0/16'

-- Populates default_variables/default_references/default_classifications
-- from the HOME_NET/EXTERNAL_NET set above; must run after they're assigned.
dofile('/usr/local/etc/snort/snort_defaults.lua')

---------------------------------------------------------------------
-- Rule path variables (Emerging Threats Open style directory layout)
---------------------------------------------------------------------
RULE_PATH = '/etc/snort/rules'

---------------------------------------------------------------------
-- Packet decoding / stream reassembly
---------------------------------------------------------------------
stream = { }
stream_ip = { }
stream_tcp = { }
stream_udp = { }

-- Detects the app-layer service on a connection so traffic gets routed to
-- the right inspector below (http_inspect, ssh, ...); without it, nothing
-- can bind and Snort fails to start ("Couldn't bind 'wizard'").
wizard = default_wizard

-- Application-layer inspectors so web + SSH attacks are parsed properly.
http_inspect = { }
ssh = { }

---------------------------------------------------------------------
-- Detection engine + ruleset ingestion
---------------------------------------------------------------------
ips =
{
    -- Snort 3 dialect copy of local.rules (see rules/local.snort3.rules for why).
    include = RULE_PATH .. '/local.snort3.rules',
    variables = default_variables,
    -- Continue even if some community rules reference unavailable options.
    mode = 'tap',   -- passive: detect + alert only, never block
}

references = default_references
classifications = default_classifications

---------------------------------------------------------------------
-- Output: compact single-line alerts to /var/log/snort/snort.log ...
-- alert_fast is line-oriented and trivially parseable by validator.py.
---------------------------------------------------------------------
alert_fast =
{
    file = true,          -- write to alert_fast.txt in the -l log dir
    packet = false,
}

-- Also emit alert_json so richer correlation is possible if desired.
alert_json =
{
    file = true,
    fields = 'timestamp action proto src_addr src_port dst_addr dst_port ' ..
             'msg sid rev priority class',
}

---------------------------------------------------------------------
-- DAQ (data acquisition) - afpacket passive capture on eth0.
---------------------------------------------------------------------
daq =
{
    module_dirs = { '/usr/local/lib/daq' },
    modules =
    {
        { name = 'afpacket', mode = 'passive' },
    },
}
