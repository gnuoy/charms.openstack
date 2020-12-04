# Copyright 2019 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import os
import re
from urllib.parse import urlparse

import charmhelpers.core.unitdata as unitdata

import charms_openstack.charm

import charmhelpers.core as ch_core
import charmhelpers.fetch as fetch
import charmhelpers.core.unitdata as unitdata

import charms.reactive as reactive


TRILIO_RELEASE_KEY = 'charmers.openstack-release-version'
TV_MOUNTS = "/var/triliovault-mounts"


class NFSShareNotMountedException(Exception):
    """Signal that the trilio nfs share is not mount"""

    pass


class UnitNotLeaderException(Exception):
    """Signal that the unit is not the application leader"""

    pass


class GhostShareAlreadyMountedException(Exception):
    """Signal that a ghost share is already mounted"""

    pass


class MismatchedConfigurationException(Exception):
    """Signal that nfs-shares and ghost-shares are mismatched"""

    pass


def _configure_triliovault_source():
    """Configure triliovault specific package sources in addition to
    any general openstack package sources (via openstack-origin)
    """
    with open(
        "/etc/apt/sources.list.d/trilio-gemfury-sources.list", "w"
    ) as tsources:
        tsources.write(ch_core.hookenv.config("triliovault-pkg-source"))


def _install_triliovault(charm):
    """Install packages dealing with Trilio nuances for upgrades as well

    Set the 'upgrade.triliovault' flag to ensure that any triliovault
    packages are upgraded.
    """
    packages = charm.all_packages
    if not reactive.is_flag_set("upgrade.triliovault"):
        packages = fetch.filter_installed_packages(
            charm.all_packages)

    if packages:
        ch_core.hookenv.status_set('maintenance',
                                   'Installing/upgrading packages')
        fetch.apt_install(packages, fatal=True)

    # AJK: we set this as charms can use it to detect installed state
    charm.set_state('{}-installed'.format(charm.name))
    charm.update_api_ports()

    # NOTE(jamespage): clear upgrade flag if set
    if reactive.is_flag_set("upgrade.triliovault"):
        reactive.clear_flag('upgrade.triliovault')


@charms_openstack.charm.core.register_get_charm_instance
def get_trillio_charm_instance(release=None, package_type='deb', *args, **kwargs):
    """Get an instance of the charm based on the release (or use the
    default if release is None).

    Note that it passes args and kwargs to the class __init__() method.

    :param release: lc string representing release wanted.
    :param package_type: string representing the package type required
    :returns: BaseOpenStackCharm() derived class according to cls.releases
    """
    trilio_releases = {}
    cls = None
    for os_release, classes in charms_openstack.charm.core._releases.items():
        trilio_releases[classes['deb'].trilio_release] = classes['deb']
    known_releases = list(reversed(list(trilio_releases.keys())))
    if release is None:
        cls = trilio_releases[known_releases[0]]
    else:
        for _release in known_releases:
            if float(release) >= float(_release):
                cls = trilio_releases[_release]
                break
    return cls(trilio_release=release, *args, **kwargs)


@charms_openstack.charm.core.register_os_release_selector
def select_trilio_release():
    release_version = unitdata.kv().get(TRILIO_RELEASE_KEY, None)
    release_version = None
    if release_version is None:
        singleton = get_trillio_charm_instance()
        try:
            release_version = singleton.get_package_version(
                singleton.release_pkg)
        except ValueError:
            # Try and make sense of deb string like:
            # 'deb [trusted=yes] https://apt.fury.io/triliodata-4-0/ /'
            deb_url = singleton.trilio_source.split()[-2]
            code = re.findall(r'-(\d*-\d*)', urlparse(deb_url).path)
            assert len(code) == 1, "Cannot derive release from {}".format(deb_url)
            release_version = code[0].replace('-', '.')
        unitdata.kv().set(TRILIO_RELEASE_KEY, release_version)
    return release_version


class TrilioVaultCharm(charms_openstack.charm.HAOpenStackCharm):
    """The TrilioVaultCharm class provides common specialisation of certain
    functions for the Trilio charm set and is designed for use alongside
    other base charms.openstack classes
    """

    abstract_class = True

    def __init__(self, **kwargs):
        super(TrilioVaultCharm, self).__init__(**kwargs)

    def configure_source(self):
        """Configure triliovault specific package sources in addition to
        any general openstack package sources (via openstack-origin)
        """
        _configure_triliovault_source()
        super().configure_source()

    def install(self):
        """Install packages dealing with Trilio nuances for upgrades as well
        """
        self.configure_source()
        _install_triliovault(self)

    def series_upgrade_complete(self):
        """Re-configure sources post series upgrade"""
        super().series_upgrade_complete()
        self.configure_source()

    @property
    def trilio_source(self):
        return hookenv.config("triliovault-pkg-source")


class TrilioVaultSubordinateCharm(charms_openstack.charm.OpenStackCharm):
    """The TrilioVaultSubordinateCharm class provides common specialisation
    of certain functions for the Trilio charm set and is designed for use
    alongside other base charms.openstack classes for subordinate charms
    """

    abstract_class = True

    def __init__(self, **kwargs):
        super(TrilioVaultSubordinateCharm, self).__init__(**kwargs)

    def configure_source(self):
        """Configure TrilioVault specific package sources
        """
        _configure_triliovault_source()
        fetch.apt_update(fatal=True)

    def install(self):
        """Install packages dealing with Trilio nuances for upgrades as well
        """
        self.configure_source()
        _install_triliovault(self)

    def series_upgrade_complete(self):
        """Re-configure sources post series upgrade"""
        super().series_upgrade_complete()
        self.configure_source()

    @property
    def trilio_source(self):
        return hookenv.config("triliovault-pkg-source")


class TrilioVaultCharmGhostAction(object):
    """Shared 'ghost share' action for TrilioVault charms

    It is designed as a mixin, and is separated out so that it is easier to
    maintain.

    i.e.

    class TrilioWLMCharm(TrilioVaultCharm,
                         TrilioVaultCharmGhostAction):
        ... stuff ...
    """

    def _encode_endpoint(self, backup_endpoint):
        """base64 encode an backup endpoint for cross mounting support"""
        return base64.b64encode(backup_endpoint.encode()).decode()

    def ghost_nfs_share(self, ghost_shares):
        """Bind mount local NFS shares to remote NFS paths

        :param ghost_shares: Comma separated NFS shares URL to ghost
        :type ghost_shares: str
        """
        ghost_shares = ghost_shares.split(',')
        nfs_shares = ch_core.hookenv.config("nfs-shares").split(',')
        try:
            share_mappings = [
                (nfs_shares[i], ghost_shares[i])
                for i in range(0, len(nfs_shares))
            ]
        except IndexError:
            raise MismatchedConfigurationException(
                "ghost-shares and nfs-shares are different lengths"
            )
        for local_share, ghost_share in share_mappings:
            self._ghost_nfs_share(local_share, ghost_share)

    def _ghost_nfs_share(self, local_share, ghost_share):
        """Bind mount a local unit NFS share to another sites location

        :param local_share: Local NFS share URL
        :type local_share: str
        :param ghost_share: NFS share URL to ghost
        :type ghost_share: str
        """
        nfs_share_path = os.path.join(
            TV_MOUNTS,
            self._encode_endpoint(local_share)
        )
        ghost_share_path = os.path.join(
            TV_MOUNTS, self._encode_endpoint(ghost_share)
        )

        current_mounts = [mount[0] for mount in ch_core.host.mounts()]

        if nfs_share_path not in current_mounts:
            # Trilio has not mounted the NFS share so return
            raise NFSShareNotMountedException(
                "nfs-share ({}) not mounted".format(
                    local_share
                )
            )

        if ghost_share_path in current_mounts:
            # bind mount already setup so return
            raise GhostShareAlreadyMountedException(
                "ghost mountpoint ({}) already bound".format(ghost_share_path)
            )

        if not os.path.exists(ghost_share_path):
            os.mkdir(ghost_share_path)

        ch_core.host.mount(nfs_share_path, ghost_share_path, options="bind")
