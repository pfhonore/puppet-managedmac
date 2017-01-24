# == Class: managedmac::filevault
#
# Leverages the Mobileconfig type to deploy a FileVault 2 profile. It provides
# only a subset of the options available to the profile and does not conform to
# the Apple defaults. Read the documentation.
#
# === Parameters
#
# [*enable*]
#   --> Whether to enable FileVault or not.
#   Type: Boolean
#
# [*use_recovery_key*]
#   Set to true to create a personal recovery key.
#   Type: Boolean
#
# [*show_recovery_key*]
#   Set to true to display the personal recovery key to the user after
#   FileVault is enabled.
#   Type: Boolean
#
# [*output_path*]
#   Path to the location where the recovery key and computer information
#   plist will be stored.
#   Type: String
#
# [*use_keychain*]
#   If set to true and no certificate information is provided in this
#   payload, the keychain already created at
#   /Library/Keychains/FileVaultMaster.keychain will be used when the
#   institutional recovery key is added.
#   Type: Boolean
#
# [*keychain_file*]
#   An absolute path or puppet:/// style URI from whence to gather an FVMI.
#   It will install and manage /Library/Keychains/FileVaultMaster.keychain.
#   Only works when $use_keychain is true.
#   Type: String
#
# [*destroy_fv_key_on_standby*]
#   Prevent saving the key across standby modes.
#   Type: Boolean
#
# [*dont_allow_fde_disable*]
#   Prevent users from disabling FDE.
#   Type: Boolean
#
# [*remove_fde*]
#   Removes FDE if $enable is false and the disk is encrypted.
#   Type: Boolean
#
# [*rsa_pubkey*]
#   An RSA public key, as a string. See example below for how this should look in hiera.
#   If present, replaces recovery key plist with an encrypted json file.
#   The encrypted file contents will be reported back to the master via a custom
#   fact, $::filevault2_recovery_key. Only the EnabledDate, SerialNumber,
#   EnabledUser, and RecoveryKey keys are stored in the encrypted recovery file
#   in order to reduce filesize. Only works when $output_path is set.
#
#   NOTE: The encrypted recovery json is created *only* when a recovery plist is
#   found– its contents are not managed by Puppet. If the encrypted recovery
#   file is removed from the node, the $::filevault2_recovery_key fact will stop
#   reporting. Reports are kept in PuppetDB for 14 days by default.
#   For a complete key escrow solution, the contents of this fact for each node
#   should be extracted from PuppetDB using a scheduled job.
#
#   To create the required rsa public key:
#   1. Generate a new ssh key.
#   https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/
#   2. Extract the public key from public certificate. This key will be used as the value for $rsa_pubkey.
#   `openssl rsa -in /foo/bar/mykey_rsa -pubout > /foo/bar/mykey_rsa.pub.pem`
#
#   Type: String
#
# === Variables
#
# Not applicable
#
# === Examples
#
# This class was designed to be used with Hiera. As such, the best way to pass
# options is to specify them in your Hiera datadir:
#
#  # Example: defaults.yaml
#  ---
# managedmac::filevault::enable: true
# managedmac::filevault::use_recovery_key: true
# managedmac::filevault::show_recovery_key: true
# managedmac::filevault::rsa_pubkey: >
#   -----BEGIN PUBLIC KEY-----
#   MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApXCDBlITs3LnTa3POPJg
#   R8P/nLWy2tbMSI7D51CPU4TxeptkCYVGEWX4wKkS6lqxtfLP9mjQcDQsOFLXKbyl
#   ...lots of base64 endcoded text...
#   uZeGNWzQkl8d8zm87NPDDfkCAwEAAQ==
#   -----END PUBLIC KEY-----
#
# Then simply, create a manifest and include the class...
#
#  # Example: my_manifest.pp
#  include managedmac::filevault
#
# If you just wish to test the functionality of this class, you could also do
# something along these lines:
#
#  class { 'managedmac::filevault':
#    enable => true,
#  }
#
# === Authors
#
# Brian Warsing <bcw@sfu.ca>
#
# === Copyright
#
# Copyright 2015 SFU, unless otherwise noted.
#
class managedmac::filevault (
  Optional[Boolean] $enable                    = undef,
  Optional[Boolean] $use_recovery_key          = undef,
  Optional[Boolean] $show_recovery_key         = undef,
  Optional[String]  $output_path               = undef,
  Optional[Boolean] $use_keychain              = undef,
  Optional[String]  $keychain_file             = undef,
  Optional[Boolean] $destroy_fv_key_on_standby = undef,
  Optional[Boolean] $dont_allow_fde_disable    = undef,
  Optional[Boolean] $remove_fde                = undef,
  Optional[String]  $rsa_pubkey                = undef,
) {

  $execpath  = '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'

  if $enable {

    if $output_path {
      validate_absolute_path($output_path)
    }

    if $use_keychain {
      if $keychain_file =~ /^puppet:/ {
        validate_re($keychain_file, 'puppet:(\/{3}(\w+\/)+\w+|\/{2}(\w+\.)+(\w+\/)+\w+)')
      } else {
        validate_absolute_path($keychain_file)
      }

      file { 'filevault_master_keychain':
        ensure => file,
        owner  => root,
        group  => wheel,
        mode   => '0644',
        path   => '/Library/Keychains/FileVaultMaster.keychain',
        source => $keychain_file;
      }
    }

    $params = {
      'com.apple.MCX.FileVault2' => {
        'Enable'          => 'On',
        'Defer'           => true,
        'UseRecoveryKey'  => $use_recovery_key,
        'ShowRecoveryKey' => $show_recovery_key,
        'OutputPath'      => $output_path,
        'UseKeychain'     => $use_keychain,
      },
      'com.apple.MCX' => {
        'DestroyFVKeyOnStandby' => $destroy_fv_key_on_standby,
        'dontAllowFDEDisable'   => $dont_allow_fde_disable,
      },
    }

    $content = process_mobileconfig_params($params)
    $organization = hiera('managedmac::organization', 'SFU')

    $ensure = $enable ? {
      true     => present,
      default  => absent,
    }

    mobileconfig { 'managedmac.filevault.alacarte':
      ensure       => $ensure,
      content      => $content,
      displayname  => 'Managed Mac: FileVault 2',
      description  => 'FileVault 2 configuration. Installed by Puppet.',
      organization => $organization,
    }

    # Encrypt the key on disk
    if $rsa_pubkey and $output_path {

      $basedir        = dirname($output_path)
      $basename       = basename($output_path, '.plist')
      $keypath        = "${::puppet_vardir}/${basename}.pub.pem"
      $encrypted_key  = '/etc/puppetlabs/puppet/filevault.json.enc.b64'

      if $rsa_pubkey !~ /^-----BEGIN PUBLIC KEY-----/ {
        fail('Failed to validate RSA public key.')
      }

      file { $keypath:
        ensure  => file,
        content => $rsa_pubkey,
        before  => Exec['plist_exists'],
      }

      exec { 'plist_exists':
        command => 'echo',
        path    => $execpath,
        onlyif  => "test -f ${output_path}",
        notify  => Exec['encrypt_recovery_key'],
      }

      # Remove unneeded keys from the plist to reduce filesize.
      # File must be < 240 bytes to be encrypted w/ rsa public key.
      exec { 'rm_hardwareuuid':
        command => "defaults delete ${output_path} HardwareUUID",
        path    => $execpath,
        onlyif  => "defaults read ${output_path} HardwareUUID",
      }

      exec { 'rm_lvguuid':
        command => "defaults delete ${output_path} LVGUUID",
        path    => $execpath,
        onlyif  => "defaults read ${output_path} LVGUUID",
      }

      exec { 'rm_lvuuid':
        command => "defaults delete ${output_path} LVUUID",
        path    => $execpath,
        onlyif  => "defaults read ${output_path} LVUUID",
      }

      exec { 'rm_pvuuid':
        command => "defaults delete ${output_path} PVUUID",
        path    => $execpath,
        onlyif  => "defaults read ${output_path} PVUUID",
      }

      # Command to convert recovery plist to JSON and encrypt with public rsa key
      $enc_cmd = "plutil -convert json ${output_path} -o - | openssl rsautl -encrypt -pubin -inkey ${keypath} | openssl base64 -out ${encrypted_key}"

      exec { 'encrypt_recovery_key':
        command     => $enc_cmd,
        path        => $execpath,
        refreshonly => true,
        require     => Exec['rm_hardwareuuid', 'rm_lvguuid', 'rm_lvuuid', 'rm_pvuuid'],
        notify      => File[$output_path],
      }

      file { $output_path:
        ensure      => absent,
        backup      => false,
        show_diff   => false,
        require     => Exec['encrypt_recovery_key'],
      }
    }

    if !$enable and $::filevault_active and $remove_fde {
      exec { 'decrypt_the_disk':
        command => '/usr/bin/fdesetup disable',
        returns => [0,1],
      }
    }

  }

}
