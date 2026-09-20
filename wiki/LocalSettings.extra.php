
# Public routing and short article URLs.
$wgServer = getenv( 'WIKI_PUBLIC_URL' );
$wgCanonicalServer = $wgServer;
$wgScriptPath = '';
$wgArticlePath = '/Wiki/$1';
$wgUsePathInfo = true;
$wgLanguageCode = 'de';

# Historical MobileFrontend build matching the bundled MediaWiki version.
wfLoadExtension( 'MobileFrontend' );
$wgMFAutodetectMobileView = true;
$wgMFDefaultSkinClass = 'SkinMinerva';

# Settings compatible with the bundled legacy MediaWiki 1.27.
$wgEnableUploads = true;
$wgAllowImageTag = false;
$wgEmailAuthentication = false;
$wgEmergencyContact = getenv( 'WIKI_CONTACT_EMAIL' ) ?: 'webmaster@example.org';
$wgPasswordSender = getenv( 'WIKI_CONTACT_EMAIL' ) ?: 'webmaster@example.org';
$wgJobRunRate = 0;
$wgShowExceptionDetails = false;
$wgShowDBErrorBacktrace = false;
$wgDebugToolbar = false;
$wgCookieSecure = true;
$wgCookieHttpOnly = true;
$wgCookieSameSite = 'Lax';

# Trust only the local reverse proxy path. HTTPS is terminated by host Nginx.
if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {
    $_SERVER['HTTPS'] = 'on';
}

# Private wiki: reading and editing require an existing account.
$wgGroupPermissions['*']['read'] = false;
$wgGroupPermissions['*']['edit'] = false;
$wgGroupPermissions['*']['createaccount'] = false;
$wgGroupPermissions['user']['read'] = true;
$wgWhitelistRead = array();
$wgWhitelistReadRegexp = array();

# Uploaded files are served through MediaWiki permission checks.
$wgUploadPath = "$wgScriptPath/img_auth.php";
$wgUploadDirectory = "$IP/images";
