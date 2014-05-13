require 'spec_helper'

describe "managedmac::hook" do



  context "when passed no params" do

    let(:title) { 'login' }

    specify do
      expect {
        should compile
      }.to raise_error(Puppet::Error, /Must pass enable/)
    end

  end

  context "name != 'login' or 'logout'" do

    let(:title) { 'foo' }

    let(:params) do
      { :enable => true, :scripts => '/etc/loginhooks' }
    end

    specify do
      expect {
        should compile
      }.to raise_error(Puppet::Error, /Parameter Error: invalid :name/)
    end

  end

  context "name == 'login' or 'logout' or derivative" do

    accepted_names = ['login', 'logout', 'LOGIN', 'LOGOUT', 'lOGiN', 'lOGOuT']
    random_name    = accepted_names[rand(accepted_names.length - 1)]

    let(:title) { random_name }

    context "when enable is not a BOOL" do
      let(:params) do
        { :enable => 'foo', :scripts => '/' }
      end
      specify do
        expect {
          should compile
        }.to raise_error(Puppet::Error, /not a boolean/)
      end
    end

    context "when enable == true" do

      let(:params) do
        { :enable => true }
      end

      context "when $scripts is set not set" do
        specify do
          expect {
            should compile
          }.to raise_error(Puppet::Error, /Must pass scripts/)
        end
      end

      context "when $scripts is not an absolute path" do
        let(:params) do
          { :enable => true, :scripts => 'whatever' }
        end
        specify do
          expect {
            should compile
          }.to raise_error(Puppet::Error, /not an absolute path/)
        end
      end

      context "when $scripts is an absolute path" do
        type = random_name.downcase
        let(:params) do
          { :enable => true, :scripts => "/etc/#{type}hooks" }
        end
        specify do
          should contain_file("/etc/#{type}hooks").with(
            { 'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'wheel',
              'mode'   => '0750',
          })
        end
        specify do
          should contain_file('/etc/masterhooks').with(
            { 'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'wheel',
              'mode'   => '0750',
          })
        end
        specify do

          should contain_file("/etc/masterhooks/#{type}hook.rb").with(
            { 'ensure' => 'file',
              'owner'  => 'root',
              'group'  => 'wheel',
              'mode'   => '0750',
          })
        end
        it { should contain_exec('activate_hook') }
      end

    end

    context "when enable == false" do
      type = random_name.downcase
      let(:params) do
        { :enable => false, :scripts => "/etc/#{type}hooks" }
      end

      it { should_not contain_file('/etc/masterhooks').with(
        { 'ensure' => 'absent',}) }

      it { should contain_file("/etc/masterhooks/#{type}hook.rb").with(
        { 'ensure' => 'absent',}) }

      it { should contain_exec('deactivate_hook') }

    end

  end

end
