# OpenStackCharm() - base class for build OpenStack charms from for the
# reactive framework.

# need/want absolute imports for the package imports to work properly
from __future__ import absolute_import

import base64
import os
import random
import string
import subprocess
import contextlib
import collections
import itertools

import six

import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.templating as os_templating
import charmhelpers.contrib.openstack.utils as os_utils
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as ch_host
import charmhelpers.core.templating
import charmhelpers.fetch
import charms.reactive.bus

import charms_openstack.ip as os_ip


# _releases{} is a dictionary of release -> class that is instantiated
# according to the the release that is being requested.  i.e. a charm can
# handle more than one release.  The OpenStackCharm() derived class sets the
# `release` variable to indicate which release that the charm supports.
# Any subsequent releases that need a different/specialised charm uses the
# `release` class property to indicate that it handles that release onwards.
_releases = {}

# `_singleton` stores the instance of the class that is being used during a
# hook invocation.
_singleton = None

# `_release_selector_function` holds a function that takes optionally takes a
# release and commutes it to another release or just returns a release.
# This is to enable the defining code to define which release is used.
_release_selector_function = None

# List of releases that OpenStackCharm based charms know about
KNOWN_RELEASES = [
    'diablo',
    'essex',
    'folsom',
    'grizzly',
    'havana',
    'icehouse',
    'juno',
    'kilo',
    'liberty',
    'mitaka',
]

VIP_KEY = "vip"
CIDR_KEY = "vip_cidr"
IFACE_KEY = "vip_iface"
APACHE_SSL_VHOST = '/etc/apache2/sites-available/openstack_https_frontend.conf'


def get_charm_instance(release=None, *args, **kwargs):
    """Get an instance of the charm based on the release (or use the
    default if release is None).

    OS releases are in alphabetical order, so it looks for the first release
    that is provided if release is None, otherwise it finds the release that is
    before or equal to the release passed.

    Note that it passes args and kwargs to the class __init__() method.

    :param release: lc string representing release wanted.
    :returns: OpenStackCharm() derived class according to cls.releases
    """
    if len(_releases.keys()) == 0:
        raise RuntimeError("No derived OpenStackCharm() classes registered")
    # Note that this relies on OS releases being in alphabetica order
    known_releases = sorted(_releases.keys())
    cls = None
    if release is None:
        # take the latest version of the charm if no release is passed.
        cls = _releases[known_releases[-1]]
    elif release < known_releases[0]:
        raise RuntimeError(
            "Release {} is not supported by this charm. Earliest support is "
            "{} release".format(release, known_releases[0]))
    else:
        # check that the release is a valid release
        if release not in KNOWN_RELEASES:
            raise RuntimeError(
                "Release {} is not a known OpenStack release?".format(release))
        # try to find the release that is supported.
        for known_release in reversed(known_releases):
            if release >= known_release:
                cls = _releases[known_release]
                break
    if cls is None:
        raise RuntimeError("Release {} is not supported".format(release))
    return cls(release=release, *args, **kwargs)


def register_os_release_selector(f):
    """Register a function that determines what the release is for the
    invocation run.  This allows the charm to define HOW the release is
    determined.

    Usage:

        @register_os_release_selector
        def my_release_selector():
            return os_release_chooser()

    The function should return a string which is an OS release.
    """
    global _release_selector_function
    if _release_selector_function is None:
        # we can only do this once in a system invocation.
        _release_selector_function = f
    else:
        raise RuntimeError(
            "Only a single release_selector_function is supported."
            " Called with {}".format(f.__name__))
    return f


class OpenStackCharmMeta(type):
    """Metaclass to provide a classproperty of 'singleton' so that class
    methods in the derived OpenStackCharm() class can simply use cls.singleton
    to get the instance of the charm.

    Thus cls.singleton is a singleton for accessing and creating the default
    OpenStackCharm() derived class.  This is to avoid a lot of boilerplate in
    the classmethods for the charm code.  This is because, usually, a
    classmethod is only called once per invocation of the script.

    Thus in the derived charm code we can do this:

        cls.singleton.instance_method(...)

    and this will instatiate the charm and call instance_method() on it.

    Note that self.singleton is also defined as a property for completeness so
    that cls.singleton and self.singleton give consistent results.
    """

    def __init__(cls, name, mro, members):
        """Receive the OpenStackCharm() (derived) class and store the release
        that it works against.  Each class defines a 'release' that it handles
        and the order of releases (as given in charmhelpers) determines (for
        any release) which OpenStackCharm() derived class is the handler for
        that class.  Note, that if the `name` is 'OpenStackCharm' then the
        function ignores the release, etc.

        :param name: string for class name.
        :param mro: tuple of base classes.
        :param members: dictionary of name to class attribute (f, p, a, etc.)
        """
        global _releases
        # Do not attempt to calculate the release for an abstract class
        if members.get('abstract_class', False):
            return
        if 'release' in members.keys():
            release = members['release']
            if release not in KNOWN_RELEASES:
                raise RuntimeError(
                    "Release {} is not a known OpenStack release"
                    .format(release))
            if release in _releases.keys():
                raise RuntimeError(
                    "Release {} defined more than once in classes {} and {} "
                    " (at least)"
                    .format(release, _releases[release].__name__, name))
            # store the class against the release.
            _releases[release] = cls
        else:
            raise RuntimeError(
                "class '{}' does not define a release that it supports. "
                "Please use the 'release' class property to define the "
                "release.".format(name))

    @property
    def singleton(cls):
        """Either returns the already created charm, or create a new one.

        This uses the _release_selector_function to choose the release is one
        has been registered, otherwise None is passed to get_charm_instance()
        """
        global _singleton
        if _singleton is None:
            release = None
            # see if a _release_selector_function has been registered.
            if _release_selector_function is not None:
                release = _release_selector_function()
            _singleton = get_charm_instance(release=release)
        return _singleton


@six.add_metaclass(OpenStackCharmMeta)
class OpenStackCharm(object):
    """
    Base class for all OpenStack Charm classes;
    encapulates general OpenStack charm payload operations

    Theory:
    Derive form this class, set the name, first_release and releases class
    variables so that get_charm_instance() will create an instance of this
    charm.

    See the other class variables for details on what they are for and do.
    """

    abstract_class = True

    # first_release = this is the first release in which this charm works
    release = 'icehouse'

    # The name of the charm (for printing, etc.)
    name = 'charmname'

    # List of packages to install
    packages = []

    # Dictionary mapping services to ports for public, admin and
    # internal endpoints
    api_ports = {}

    # Keystone endpoint type
    service_type = None

    # Default service for the charm
    default_service = None

    # A dictionary of:
    # {
    #    'config.file': ['list', 'of', 'services', 'to', 'restart'],
    #    'config2.file': ['more', 'services'],
    # }
    restart_map = {}

    # The list of required services that are checked for assess_status
    # e.g. required_relations = ['identity-service', 'shared-db']
    required_relations = []

    # The command used to sync the database
    sync_cmd = []

    # The list of services that this charm manages
    services = []

    # The adapters class that this charm uses to adapt interfaces.
    adapters_class = None

    ha_resources = []
    adapters_class = None
    HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'

    @property
    def singleton(self):
        """Return the only instance of the charm class in this run"""
        # Note refers back to the Metaclass property for this charm.
        return self.__class__.singleton

    def __init__(self, interfaces=None, config=None, release=None):
        """Instantiate an instance of the class.

        Sets up self.config and self.adapter_instance if cls.adapters_class and
        interfaces has been set.

        :param interfaces: list of interface instances for the charm.
        :param config: the config for the charm (optionally None for
        automatically using config())
        """
        self.config = config or hookenv.config()
        self.release = release
        self.adapters_instance = None
        if interfaces and self.adapters_class:
            self.adapters_instance = self.adapters_class(interfaces)

    @property
    def all_packages(self):
        """List of packages to be installed

        @return ['pkg1', 'pkg2', ...]
        """
        return self.packages

    @property
    def full_restart_map(self):
        """Map of services to be restarted if a file changes

        @return {
                    'file1': ['svc1', 'svc3'],
                    'file2': ['svc2', 'svc3'],
                    ...
                }
        """
        return self.restart_map

    def install(self):
        """Install packages related to this charm based on
        contents of self.packages attribute.
        """
        packages = charmhelpers.fetch.filter_installed_packages(
            self.all_packages)
        if packages:
            hookenv.status_set('maintenance', 'Installing packages')
            charmhelpers.fetch.apt_install(packages, fatal=True)
        self.set_state('{}-installed'.format(self.name))
        hookenv.status_set('maintenance',
                           'Installation complete - awaiting next status')

    def set_state(self, state, value=None):
        """proxy for charms.reactive.bus.set_state()"""
        charms.reactive.bus.set_state(state, value)

    def remove_state(self, state):
        """proxy for charms.reactive.bus.remove_state()"""
        charms.reactive.bus.remove_state(state)

    def get_state(self, state):
        """proxy for charms.reactive.bus.get_state()"""
        return charms.reactive.bus.get_state(state)

    def api_port(self, service, endpoint_type=os_ip.PUBLIC):
        """Return the API port for a particular endpoint type from the
        self.api_ports{}.

        :param service: string for service name
        :param endpoing_type: one of charm.openstack.ip.PUBLIC| INTERNAL| ADMIN
        :returns: port (int)
        """
        return self.api_ports[service][endpoint_type]

    def configure_source(self):
        """Configure installation source using the config item
        'openstack-origin'

        This configures the installation source for deb packages and then
        updates the packages list on the unit.
        """
        os_utils.configure_installation_source(self.config['openstack-origin'])
        charmhelpers.fetch.apt_update(fatal=True)

    @property
    def region(self):
        """Return the OpenStack Region as contained in the config item 'region'
        """
        return self.config['region']

    @property
    def public_url(self):
        """Return the public endpoint URL for the default service as specified
        in the self.default_service attribute
        """
        return "{}:{}".format(os_ip.canonical_url(os_ip.PUBLIC),
                              self.api_port(self.default_service,
                                            os_ip.PUBLIC))

    @property
    def admin_url(self):
        """Return the admin endpoint URL for the default service as specificed
        in the self.default_service attribute
        """
        return "{}:{}".format(os_ip.canonical_url(os_ip.ADMIN),
                              self.api_port(self.default_service,
                                            os_ip.ADMIN))

    @property
    def internal_url(self):
        """Return the internal internal endpoint URL for the default service as
        specificated in the self.default_service attribtue
        """
        return "{}:{}".format(os_ip.canonical_url(os_ip.INTERNAL),
                              self.api_port(self.default_service,
                                            os_ip.INTERNAL))

    @contextlib.contextmanager
    def restart_on_change(self):
        """Restart the services in the self.restart_map{} attribute if any of
        the files identified by the keys changes for the wrapped call.

        This function is a @decorator that checks if the wrapped function
        changes any of the files identified by the keys in the
        self.restart_map{} and, if they change, restarts the services in the
        corresponding list.
        """
        checksums = {path: ch_host.path_hash(path)
                     for path in self.full_restart_map.keys()}
        yield
        restarts = []
        for path in self.full_restart_map:
            if ch_host.path_hash(path) != checksums[path]:
                restarts += self.full_restart_map[path]
        services_list = list(collections.OrderedDict.fromkeys(restarts).keys())
        for service_name in services_list:
            ch_host.service_stop(service_name)
        for service_name in services_list:
            ch_host.service_start(service_name)

    def render_all_configs(self, adapters_instance=None):
        """Render (write) all of the config files identified as the keys in the
        self.restart_map{}

        Note: If the config file changes on storage as a result of the config
        file being written, then the services are restarted as per
        the restart_the_services() method.

        If adapters_instance is None then the self.adapters_instance is used
        that was setup in the __init__() method.

        :param adapters_instance: [optional] the adapters_instance to use.
        """
        self.render_configs(self.full_restart_map.keys(),
                            adapters_instance=adapters_instance)

    def render_configs(self, configs, adapters_instance=None):
        """Render the configuration files identified in the list passed as
        configs.

        If adapters_instance is None then the self.adapters_instance is used
        that was setup in the __init__() method.

        :param configs: list of strings, the names of the configuration files.
        :param adapters_instance: [optional] the adapters_instance to use.
        """
        if adapters_instance is None:
            adapters_instance = self.adapters_instance
        with self.restart_on_change():
            for conf in configs:
                charmhelpers.core.templating.render(
                    source=os.path.basename(conf),
                    template_loader=os_templating.get_loader(
                        'templates/', self.release),
                    target=conf,
                    context=adapters_instance)

    def render_with_interfaces(self, interfaces, configs=None):
        """Render the configs using the interfaces passed; overrides any
        interfaces passed in the instance creation.

        :param interfaces: list of interface objects to render against
        """
        if not configs:
            configs = self.full_restart_map.keys()
        self.render_configs(
            configs,
            adapters_instance=self.adapters_class(interfaces))

    def restart_all(self):
        """Restart all the services configured in the self.services[]
        attribute.
        """
        for svc in self.services:
            ch_host.service_restart(svc)

    def db_sync_done(self):
        return hookenv.leader_get(attribute='db-sync-done')

    def db_sync(self):
        """Perform a database sync using the command defined in the
        self.sync_cmd attribute. The services defined in self.services are
        restarted after the database sync.
        """
        if not self.db_sync_done() and hookenv.is_leader():
            subprocess.check_call(self.sync_cmd)
            hookenv.leader_set({'db-sync-done': True})
            # Restart services immediately after db sync as
            # render_domain_config needs a working system
            self.restart_all()

    def assess_status(self):
        """Assess the status of the unit and set the status and a useful
        message as appropriate.

        The 3 checks are:

         1. Check if the unit has been paused (using
            os_utils.is_unit_paused_set().
         2. Check if the interfaces are all present (using the states that are
            set by each interface as it comes 'live'.
         3. Do a custom_assess_status_check() check.
         4. Check that services that should be running are running.

        Each sub-function determins what checks are taking place.

        If custom assess_status() functionality is required then the derived
        class should override any of the 4 check functions to alter the
        behaviour as required.

        Note that if ports are NOT to be checked, then the derived class should
        override :meth:`ports_to_check()` and return an empty list.

        SIDE EFFECT: this function calls status_set(state, message) to set the
        workload status in juju.
        """
        for f in [self.check_if_paused,
                  self.check_interfaces,
                  self.custom_assess_status_check,
                  self.check_services_running]:
            state, message = f()
            if state is not None:
                hookenv.status_set(state, message)
                return
        # No state was particularly set, so assume the unit is active
        hookenv.status_set('active', 'Unit is ready')

    def custom_assess_status_check(self):
        """Override this function in a derived class if there are any other
        status checks that need to be done that aren't about relations, etc.

        Return (None, None) if the status is okay (i.e. the unit is active).
        Return ('active', message) do shortcut and force the unit to the active
        status.
        Return (other_status, message) to set the status to desired state.

        :returns: None, None - no action in this function.
        """
        return None, None

    def check_if_paused(self):
        """Check if the unit is paused and return either the paused status,
        message or None, None if the unit is not paused.  If the unit is paused
        but a service is incorrectly running, then the function returns a
        broken status.

        :returns: (status, message) or (None, None)
        """
        return os_utils._ows_check_if_paused(
            services=self.services,
            ports=self.ports_to_check(self.api_ports))

    def check_interfaces(self):
        """Check that the required interfaces have both connected and availble
        states set.

        This requires a convention from the OS interfaces that they set the
        '{relation_name}.connected' state on connection, and the
        '{relation_name}.available' state when the connection information is
        available and the interface is ready to go.

        The interfaces (relations) that are checked are named in
        self.required_relations which is a list of strings representing the
        generic relation name.  e.g. 'identity-service' rather than 'keystone'.

        Returns (None, None) if the interfaces are okay, or a status, message
        if any of the interfaces are not ready.

        Derived classes can augment/alter the checks done by overriding the
        companion method :property:`states_to_check` which converts a relation
        into the states to confirm existence, along with the error message.

        :returns (status, message) or (None, None)
        """
        states_to_check = self.states_to_check()
        # bail if there is nothing to do.
        if not states_to_check:
            return None, None
        available_states = charms.reactive.bus.get_states().keys()
        status = None
        messages = []
        for relation, states in states_to_check.items():
            for state, err_status, err_msg in states:
                if state not in available_states:
                    messages.append(err_msg)
                    status = os_utils.workload_state_compare(status,
                                                             err_status)
                    # as soon as we error on a relation, skip to the next one.
                    break
        if status is not None:
            return status, ", ".join(messages)
        # Everything is fine.
        return None, None

    def states_to_check(self):
        """Construct a default set of connected and available states for each
        of the relations passed, along with error messages and new status
        conditions if they are missing.

        The method returns a {relation: [(state, err_status, err_msg), (...),]}
        This corresponds to the relation, the state to check for, the error
        status to set if that state is missing, and the message to show if the
        state is missing.

        The list of tuples is evaulated in order for each relation, and stops
        after the first failure.  This means that it doesn't check (say)
        available if connected is not available.
        """
        states_to_check = collections.OrderedDict()
        for relation in self.required_relations:
            states_to_check[relation] = [
                ("{}.connected".format(relation),
                 "blocked",
                 "'{}' missing".format(relation)),
                ("{}.available".format(relation),
                 "waiting",
                 "'{}' incomplete".format(relation))]
        return states_to_check

    def check_services_running(self):
        """Check that the services that should be running are actually running.

        This uses the self.services and self.api_ports to determine what should
        be checked.

        :returns: (status, message) or (None, None).
        """
        # This returns either a None, None or a status, message if the service
        # is not running or the ports are not open.
        return os_utils._ows_check_services_running(
            services=self.services,
            ports=self.ports_to_check(self.api_ports))

    def ports_to_check(self, ports):
        """Return a flattened, sorted, unique list of ports from self.api_ports

        NOTE. To disable port checking, simply override this method in the
        derived class and return an empty [].

        :param ports: {key: {subkey: value}}
        :returns: [value1, value2, ...]
        """
        # NB self.api_ports = {key: {space: value}}
        # The chain .. map  flattens all the values into a single list
        return sorted(set(itertools.chain(*map(lambda x: x.values(),
                                               self.api_ports.values()))))


class HAOpenStackCharm(OpenStackCharm):

    abstract_class = True

    def __init__(self, **kwargs):
        super(HAOpenStackCharm, self).__init__(**kwargs)
        self.set_haproxy_stat_password()
        self.set_config_defined_certs_and_keys()

    @property
    def apache_vhost_file(self):
        """Apache vhost for SSL termination

        :returns: string
        """
        return APACHE_SSL_VHOST

    def enable_apache_ssl_vhost(self):
        """Enable Apache vhost for SSL termination

        Enable Apache vhost for SSL termination if vhost exists and it is not
        curently enabled
        """
        if os.path.exists(self.apache_vhost_file):
            check_enabled = subprocess.call(
                ['a2query', '-s', 'openstack_https_frontend'])
            if check_enabled != 0:
                subprocess.check_call(['a2ensite', 'openstack_https_frontend'])
                ch_host.service_reload('apache2', restart_on_failure=True)

    def configure_apache(self):
        if self.apache_enabled():
            self.install()
            self.enable_apache_modules()
            self.enable_apache_ssl_vhost()

    @property
    def all_packages(self):
        """List of packages to be installed

        @return ['pkg1', 'pkg2', ...]
        """
        _packages = self.packages[:]
        if self.haproxy_enabled():
            _packages.append('haproxy')
        if self.apache_enabled():
            _packages.append('apache2')
        return _packages

    @property
    def full_restart_map(self):
        """Map of services to be restarted if a file changes

        @return {
                    'file1': ['svc1', 'svc3'],
                    'file2': ['svc2', 'svc3'],
                    ...
                }
        """
        _restart_map = self.restart_map.copy()
        if self.haproxy_enabled():
            _restart_map[self.HAPROXY_CONF] = ['haproxy']
        if self.apache_enabled():
            _restart_map[self.apache_vhost_file] = ['apache2']
        return _restart_map

    def apache_enabled(self):
        """Determine if apache is being used

        @return True if apache is being used"""
        return self.get_state('ssl.enabled')

    def haproxy_enabled(self):
        """Determine if haproxy is fronting the services

        @return True if haproxy is fronting the service"""
        return 'haproxy' in self.ha_resources

    def configure_ha_resources(self, hacluster):
        """Inform the ha subordinate about each service it should manage. The
        child class specifies the services via self.ha_resources

        @param hacluster instance of interface class HAClusterRequires
        """
        RESOURCE_TYPES = {
            'vips': self._add_ha_vips_config,
            'haproxy': self._add_ha_haproxy_config,
        }
        if self.ha_resources:
            for res_type in self.ha_resources:
                RESOURCE_TYPES[res_type](hacluster)
            hacluster.bind_resources(iface=self.config[IFACE_KEY])

    def _add_ha_vips_config(self, hacluster):
        """Add a VirtualIP object for each user specified vip to self.resources

        @param hacluster instance of interface class HAClusterRequires
        """
        for vip in self.config.get(VIP_KEY, '').split():
            iface = (ch_ip.get_iface_for_address(vip) or
                     self.config.get(IFACE_KEY))
            netmask = (ch_ip.get_netmask_for_address(vip) or
                       self.config.get(CIDR_KEY))
            if iface is not None:
                hacluster.add_vip(self.name, vip, iface, netmask)

    def _add_ha_haproxy_config(self, hacluster):
        """Add a InitService object for haproxy to self.resources

        @param hacluster instance of interface class HAClusterRequires
        """
        hacluster.add_init_service(self.name, 'haproxy')

    def set_haproxy_stat_password(self):
        """Set a stats password for accessing haproxy statistics"""
        if not self.get_state('haproxy.stat.password'):
            password = ''.join([
                random.choice(string.ascii_letters + string.digits)
                for n in range(32)])
            self.set_state('haproxy.stat.password', password)

    def enable_apache_modules(self):
        """Enable Apache modules needed for SSL termination"""
        restart = False
        for module in ['ssl', 'proxy', 'proxy_http']:
            check_enabled = subprocess.call(['a2query', '-m', module])
            if check_enabled != 0:
                subprocess.check_call(['a2enmod', module])
                restart = True
        if restart:
            ch_host.service_restart('apache2')

    def configure_cert(self, cert, key, cn=None):
        """Configure service SSL cert and key

        Write out service SSL certificate and key for Apache.

        @param cert string SSL Certificate
        @param key string SSL Key
        @param cn string Canonical name for service
        """
        if not cn:
            cn = os_ip.resolve_address(endpoint_type=os_ip.INTERNAL)
        ssl_dir = os.path.join('/etc/apache2/ssl/', self.name)
        ch_host.mkdir(path=ssl_dir)
        if cn:
            cert_filename = 'cert_{}'.format(cn)
            key_filename = 'key_{}'.format(cn)
        else:
            cert_filename = 'cert'
            key_filename = 'key'

        ch_host.write_file(path=os.path.join(ssl_dir, cert_filename),
                           content=cert.encode('utf-8'))
        ch_host.write_file(path=os.path.join(ssl_dir, key_filename),
                           content=key.encode('utf-8'))

    def get_local_addresses(self):
        """Return list of local addresses on each configured network

        For each network return an address the local unit has on that network
        if one exists.

        @returns [private_addr, admin_addr, public_addr, ...]
        """
        addresses = [
            os_utils.get_host_ip(hookenv.unit_get('private-address'))]
        for addr_type in os_ip.ADDRESS_MAP.keys():
            laddr = os_ip.resolve_address(endpoint_type=addr_type)
            if laddr:
                addresses.append(laddr)
        return sorted(list(set(addresses)))

    def get_certs_and_keys(self, keystone_interface=None):
        """Collect SSL config for local endpoints

        SSL keys and certs may come from user specified configuration for this
        charm or they may come directly from Keystone.

        If collecting from keystone there may be a certificate and key per
        endpoint (public, admin etc).

        @returns [
            {'key': 'key1', 'cert': 'cert1', 'ca': 'ca1', 'cn': 'cn1'}
            {'key': 'key2', 'cert': 'cert2', 'ca': 'ca2', 'cn': 'cn2'}
            ...
        ]
        """
        if self.config_defined_ssl_key and self.config_defined_ssl_cert:
            return [{
                'key': self.config_defined_ssl_key.decode('utf-8'),
                'cert': self.config_defined_ssl_cert.decode('utf-8'),
                'ca': self.config_defined_ssl_ca.decode('utf-8'),
                'cn': None}]
        elif keystone_interface:
            keys_and_certs = []
            for addr in self.get_local_addresses():
                key = keystone_interface.get_ssl_key(addr)
                cert = keystone_interface.get_ssl_cert(addr)
                ca = keystone_interface.get_ssl_ca()
                if key and cert:
                    keys_and_certs.append({
                        'key': key,
                        'cert': cert,
                        'ca': ca,
                        'cn': addr})
            return keys_and_certs
        else:
            return []

    def set_config_defined_certs_and_keys(self):
        """Set class attributes for user defined ssl options

        Inspect user defined SSL config and set
        config_defined_{ssl_key, ssl_cert, ssl_ca}
        """
        for ssl_param in ['ssl_key', 'ssl_cert', 'ssl_ca']:
            key = 'config_defined_{}'.format(ssl_param)
            if self.config.get(ssl_param):
                setattr(self, key,
                        base64.b64decode(self.config.get(ssl_param)))
            else:
                setattr(self, key, None)

    def configure_ssl(self, keystone_interface=None):
        """Configure SSL certificates and keys

        @param keystone_interface KeystoneRequires class
        """
        ssl_objects = self.get_certs_and_keys(
            keystone_interface=keystone_interface)
        if ssl_objects:
            for ssl in ssl_objects:
                self.configure_cert(ssl['cert'], ssl['key'], cn=ssl['cn'])
                self.configure_ca(ssl['ca'], update_certs=False)
            self.run_update_certs()
            self.set_state('ssl.enabled', True)
            self.configure_apache()
        else:
            self.set_state('ssl.enabled', False)

    def configure_ca(self, ca_cert, update_certs=True):
        """Write Certificate Authority certificate"""
        cert_file = \
            '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'
        if ca_cert:
            with open(cert_file, 'w') as crt:
                crt.write(ca_cert)
            if update_certs:
                self.run_update_certs()

    def run_update_certs(self):
        """Update certifiacte

        Run update-ca-certificates to update the directory /etc/ssl/certs to
        hold SSL certificates and generates ca-certificates.crt, a concatenated
        single-file list of certificates
        """
        subprocess.check_call(['update-ca-certificates', '--fresh'])

    def update_peers(self, cluster):
        for addr_type in os_ip.ADDRESS_MAP.keys():
            cidr = self.config.get(os_ip.ADDRESS_MAP[addr_type]['config'])
            laddr = ch_ip.get_address_in_network(cidr)
            if laddr:
                cluster.set_address(
                    os_ip.ADDRESS_MAP[addr_type]['binding'],
                    laddr)
