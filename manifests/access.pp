define pam::access (
  $permission,
  $origin,
  $entity   = $title,
  $ensure   = present,
  $priority = '10'
) {
  include pam

  if ! ($osfamily in ['Debian', 'RedHat', 'Suse']) {
    fail("pam::access does not support osfamily ${osfamily}")
  }

  if ! ($permission in ['+', '-']) {
    fail("Permiision must be + or - ; recieved ${permission}")
  }

  concat::fragment { "pam::access ${permission}${entity}${origin}":
    ensure  => $ensure,
    target  => '/etc/security/access.conf',
    content => "${permission}:${entity}:${origin}\n",
    order   => $priority
  }
}
