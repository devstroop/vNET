Name:           vnet
Version:        %{vnet_version}
Release:        %{vnet_release}
Summary:        Portable virtual router
License:        Apache-2.0
URL:            https://github.com/devstroop/vnet
BuildArch:      %{vnet_arch}
AutoReqProv:    no
%global __os_install_post %{nil}

%description
vNET provides L2/L3 forwarding, bridging, NAT, DHCP, DNS and a
stateful firewall for Linux. This package contains vnet, vnetd,
the systemd unit, the C ABI library and the user documentation.

%prep
%build
%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a %{vnet_stage}/. %{buildroot}/

%post
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl stop vnetd.service >/dev/null 2>&1 || :
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%dir /etc/vnet
%config(noreplace) /etc/vnet/vnet.json.example
/lib/systemd/system/vnetd.service
/usr/bin/vnet
/usr/bin/vnetd
/usr/include/vnet.h
/usr/lib/libvnet.a
/usr/lib/libvnet.so*
%dir /usr/share/doc/vnet
/usr/share/doc/vnet/*

%changelog
