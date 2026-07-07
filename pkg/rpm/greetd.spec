Name:           greetd
Epoch:          1
Version: 0.10.3
Release:        1%{?dist}
Summary:        greetd login manager daemon (Playtron fork)

License:        GPL-3.0-only
URL:            https://git.sr.ht/~kennylevinsen/greetd
Source0:        %{name}-%{_arch}.tar.gz

%global debug_package %{nil}

Requires:       systemd
Requires:       pam

# The %%post/%%preun/%%postun scriptlets provision the greetd system user
# (systemd-sysusers), its state dir (systemd-tmpfiles) and register the unit
# (systemd-update-helper) on the target host.
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

# Playtron fork of greetd (adds overlap_handoff + seatless-session support).
# Carry Epoch:1 so this package supersedes Fedora's stock greetd (Epoch:0) on a
# routine `dnf update` regardless of its release number, and Obsoletes the
# lower-epoch build so it is cleanly replaced.
Provides:       greetd = %{epoch}:%{version}-%{release}
Obsoletes:      greetd < %{epoch}:%{version}

%description
greetd is a minimal and flexible login manager daemon that makes no assumptions
about what you want to launch. This is the Playtron fork, adding overlap_handoff
and seatless-session support. Ships both the greetd daemon and the bundled
agreety text greeter.

%prep
%autosetup -n %{name} -p1

%build

%install
install -Dm0755 "usr/bin/greetd"  "%{buildroot}%{_bindir}/greetd"
install -Dm0755 "usr/bin/agreety" "%{buildroot}%{_bindir}/agreety"
install -Dm0644 "usr/lib/systemd/system/greetd.service" "%{buildroot}%{_prefix}/lib/systemd/system/greetd.service"
install -Dm0644 "usr/lib/sysusers.d/greetd.conf" "%{buildroot}%{_prefix}/lib/sysusers.d/greetd.conf"
install -Dm0644 "usr/lib/tmpfiles.d/greetd.conf" "%{buildroot}%{_prefix}/lib/tmpfiles.d/greetd.conf"
install -Dm0644 "etc/greetd/config.toml" "%{buildroot}%{_sysconfdir}/greetd/config.toml"
install -Dm0644 "etc/pam.d/greetd" "%{buildroot}%{_sysconfdir}/pam.d/greetd"
install -Dm0644 "etc/pam.d/greetd-greeter" "%{buildroot}%{_sysconfdir}/pam.d/greetd-greeter"
install -Dm0644 "usr/share/licenses/greetd/LICENSE" "%{buildroot}%{_datadir}/licenses/greetd/LICENSE"

%post
# Provision the greetd system user/group and its state dir on the target host.
systemd-sysusers /usr/lib/sysusers.d/greetd.conf >/dev/null 2>&1 || :
systemd-tmpfiles --create /usr/lib/tmpfiles.d/greetd.conf >/dev/null 2>&1 || :
# Register the greetd.service unit on initial installation only.
if [ $1 -eq 1 ] && [ -x /usr/lib/systemd/systemd-update-helper ]; then
    /usr/lib/systemd/systemd-update-helper install-system-units greetd.service || :
fi

%preun
# Package removal, not upgrade.
if [ $1 -eq 0 ] && [ -x /usr/lib/systemd/systemd-update-helper ]; then
    /usr/lib/systemd/systemd-update-helper remove-system-units greetd.service || :
fi

%postun
# Upgrade: mark the unit for restart.
if [ $1 -ge 1 ] && [ -x /usr/lib/systemd/systemd-update-helper ]; then
    /usr/lib/systemd/systemd-update-helper mark-restart-system-units greetd.service || :
fi

%files
%license %{_datadir}/licenses/greetd/LICENSE
%{_bindir}/greetd
%{_bindir}/agreety
%{_prefix}/lib/systemd/system/greetd.service
%{_prefix}/lib/sysusers.d/greetd.conf
%{_prefix}/lib/tmpfiles.d/greetd.conf
%dir %{_sysconfdir}/greetd
%config(noreplace) %{_sysconfdir}/greetd/config.toml
%config(noreplace) %{_sysconfdir}/pam.d/greetd
%config(noreplace) %{_sysconfdir}/pam.d/greetd-greeter

%changelog
* Mon Jul 06 2026 Playtron <dev@playtron.one> - 1:0.10.3-1
- Initial RPM package for the Playtron greetd fork (overlap_handoff + seatless
  session support). Packages greetd + agreety, the greetd.service unit, the
  default /etc/greetd/config.toml, the greetd/greetd-greeter PAM services, and
  the greetd system user via sysusers.d/tmpfiles.d. Carries Epoch:1 so it
  supersedes Fedora's stock greetd.
