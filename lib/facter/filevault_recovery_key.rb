# filevault_recovery_key.rb

Facter.add(:filevault_recovery_key) do
  confine :kernel => 'Darwin'
  setcode do
  	keyfile = '/etc/puppetlabs/puppet/filevault.json.enc.b64'
  	if File.exist? keyfile
      File.read keyfile
    end
  end
end
