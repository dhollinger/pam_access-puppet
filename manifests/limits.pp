define pam::limits (
  $domain,
  $type,
  $item,
  $value,
  $ensure   = present,
  $priority = '10'
) {
  include pam

  if ! ($osfamily in ['Debian', 'RedHat', 'Suse']) {
    fail("pam::limits does not support osfamily $osfamily")
  }

  concat::fragment { "pam::limits ${domain}-${type}-${item}-${value}":
    ensure  => $ensure,
    target  => '/etc/security/limits.conf',
    content => "${domain} ${type} ${item} ${value}\n",
    order   => $priority,
  }

}
