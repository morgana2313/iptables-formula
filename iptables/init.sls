# Firewall management module
{%- if salt['pillar.get']('firewall:enabled') %}
  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {% set install = firewall.get('install', False) %}
  {% set strict_mode = firewall.get('strict', False) %}
  {% set global_block_nomatch = firewall.get('block_nomatch', False) %}
  {% set ipv6_en = firewall.get('ipv6_enable', False) %}
  {% set initial_flush = firewall.get('initial_flush', False) %}
  {% set packages = salt['grains.filter_by']({
    'Debian': ['iptables', 'iptables-persistent'],
    'RedHat': ['iptables'],
    'default': 'Debian'}) %}

    {%- if install %}
      # Install required packages for firewalling
      iptables_packages:
        pkg.installed:
          - pkgs:
            {%- for pkg in packages %}
            - {{pkg}}
            {%- endfor %}
    {%- endif %}



      iptables_initial_flush:
        # https://serverfault.com/questions/200635/best-way-to-clear-all-iptables-rules
        # iptables -X  alike option to delete all chains not supported in saltstack iptables state.
        cmd.run:
          - name: |
              {%- if initial_flush %}
              iptables -P INPUT ACCEPT
              iptables -P FORWARD ACCEPT
              iptables -P OUTPUT ACCEPT
              iptables -t nat -F
              iptables -t mangle -F
              iptables -F
              iptables -X
                {%- if ipv6_en %}
              ip6tables -P INPUT ACCEPT
              ip6tables -P FORWARD ACCEPT
              ip6tables -P OUTPUT ACCEPT
              ip6tables -t nat -F
              ip6tables -t mangle -F
              ip6tables -F
              ip6tables -X
                {%- endif %}
              {%- else %} {# Effective No Operation #}
              true
              {%- endif %}

    {%- if strict_mode %}
      # If the firewall is set to strict mode, we'll need to allow some
      # that always need access to anything
      iptables_allow_localhost:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.1
          - save: True
          - require:
            - iptables_initial_flush
      {% if ipv6_en %}
      iptables_allow_localhost_v6:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - source: ::1
          - save: True
          - require:
            - iptables_initial_flush
      {% endif %}

      # Allow related/established sessions
      iptables_allow_established:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True
          - require:
            - iptables_initial_flush
      {% if ipv6_en %}
      iptables_allow_established_v6:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - family: ipv6
          - save: True
          - require:
            - iptables_initial_flush
      {% endif %}

      # Set the policy to deny everything unless defined
      enable_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: DROP
          - save: True
          - require:
            - iptables: iptables_allow_localhost
            - iptables: iptables_allow_established
      {% if ipv6_en %}
      enable_reject_policy_v6:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: DROP
          - family: ipv6
          - save: True
          - require:
            - iptables: iptables_allow_localhost
            - iptables: iptables_allow_established
      {% endif %}
    {%- endif %}

  # Generate ipsets for all services that we have information about
  {%- for service_name, service_details in firewall.get('services', {}).items() %}
    {% set block_nomatch = service_details.get('block_nomatch', False) %}
    {% set interfaces = service_details.get('interfaces','') %}
    {% set protos = service_details.get('protos',['tcp']) %}
    {% if service_details.get('comment', False) %}
      {% set comment = '- comment: ' + service_details.get('comment') %}
    {% else %}
      {% set comment = '' %}
    {% endif %}

    # Allow rules for ips/subnets
    {%- for ip in service_details.get('ips_allow', []) %}
      {%- set ip_fam='ipv4' if (ipv6_en and (ip | regex_match('.*:')) is none) else 'ipv6' %}
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: {{ ip_fam }}
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          - require:
            - iptables_initial_flush
          {{ comment }}
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}_{{interface}}:
        iptables.append:
          - table: filter
