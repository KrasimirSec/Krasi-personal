<?php
if ( !preg_match('/^64\.202\.|^172\.|^216\.69\./', $_SERVER['REMOTE_ADDR']) ) { //limit access by IP
	header("HTTP/1.1 403 Forbidden");
	header("Content-Type: text/plain");
	echo 'Access denied to ' . $_SERVER['REMOTE_ADDR'] . ' by IP rule.';
	exit;
}
?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head><title>Wordpress Integrity Check</title></head>
<body>
<?php
ini_set('max_execution_time', '30000');
ini_set('set_time_limit', '30000');
ini_set('display_errors', '1');

define('STATUS_MISSING', 0);
define('STATUS_OK', 1);
define('STATUS_ANCIENT', 2);
define('STATUS_WRONGVERSION', 3);
define('STATUS_CORRUPT', 4);
define('STATUS_UNKNOWN', 5);

//these files are treated as OK if they are missing
$missingok =  array('license.txt',
					'readme.html',
					'wp-includes/.htaccess',
					'wp-admin/install.php',
					'wp-admin/upgrade.php',
					'wp-config-sample.php');
//these files are treated as OK if they are unknown
$unknownok =  array('.htaccess',
					'wp-config.php',
					'wordpress_core_integrity.php');

//get wordpress version
if ( file_exists('wp-includes/version.php') ) {
	$wpversionfile = file_get_contents('wp-includes/version.php');
	$matchcount = preg_match_all('@\$wp_version \= \'([\d\.]+)\'\;@', $wpversionfile, $match);
	if ( $matchcount ) {
		$wpversion = str_replace('.', '', $match[1][0]);
		$wpversion .= strlen($wpversion) < 3 ? '0' : '';
		$wpversion = intval($wpversion);
	} else {
		die('Could not determine version from wp-includes/version.php file.');
	}
} else {
	die('wp-includes/version.php does not exist. You\'re going to have a bad time.');
}
echo '<h1>Wordpress ' . $match[1][0] . "</h1>\r\n";
if ( $wpversion < 320 ) {
	echo 'The wordpress version detected is less than 3.2. Abandon all hope, ye who enter here.';
	exit;
}

//This url should contain whitespace-cleaned md4 hashes, sizes, and paths for all wordpress versions from 3.2 to current
//With these keys:     0:status 1:filesize 2:filepath 3:minversion 4:maxversion

//In case this ever needs to be rebuilt, show this to people, and when you find one that knows 
//just what it means, they ought to have the skills to make use of it: 
//PD9waHAKLyoKbm90ZXM6ClRoaXMgc2NyaXB0IGdlbmVyYXRlcyBhIGhhc2hlcy50eHQgZmlsZSwgd2hpY2ggY29udGFpbnMgYSBzZXJpYWxpemVkIGFycmF5IG9mIGFsbCBmaWxlcyBmcm9tCndvcmRwcmVzcyAzLjIgdXAgdG8gY3VycmVudCwgaW5jbHVkaW5nIGEgaGFzaCwgc2l6ZSwgbWluIGFuZCBtYXggd29yZHByZXNzIHZlcnNpb24sIGFuZCBwYXRoLgoKVGhlIGZpbGUgd3AtaW5jbHVkZXMvU2ltcGxlUGllL1BhcnNlL0RhdGUucGhwIHdhcyBmb3VuZCB0byBiZSBiaXphYXIuIEkgZm91bmQgdGhhdCB3aGVuIHJlYWRpbmcgdGhpcyBmaWxlLCAKcmVnYXJkbGVzcyBvZiB0aGUgZnVuY3Rpb25zIHVzZWQsIGl0IGN1dHMgb2ZmIHRoZSBmaXJzdCBwYXJ0IG9mIHRoZSBmaWxlLiBJdCBzZWVtcyB0byBkbyBkaWZmZXJlbnQKZnJvbSBjb21tYW5kIGxpbmUgcGhwIHZzIGZyb20gd2ViIGJyb3dzZXIuIEkgd2FzIG5vdCBhYmxlIHRvIGRldGVybWluZSB3aHksIHNvIEkgZW5kZWQgdXAgc3RvcmluZyAKYm90aCBoYXNoZXMuIFRoaXMgaXMgd2h5IHRoZSBzY3JpcHQgbWVyZ2VzIGluIHRoZSBvbGQgYXJyYXksIHRvIGdldCB0aGVzZSBvbmUgb2ZmIHRoaW5ncy4gVXN1YWxseSAKd2UgYWxzbyBuZWVkIHRvIG1hbnVhbGx5IHVwZGF0ZSBoYXNoIDc1MmQ0YTNiOThlZmFiYzIwZDczNjMwZmU3MzljNjE2IHRvIHRoZSBsYXRlc3QgdmVyc2lvbi4gCgpGb3IgYmluYXJ5IGZpbGVzIHN1Y2ggYXMgaW1hZ2VzLCBvbmx5IHRoZSBmaWxlIHNpemUgaXMgY29tcGFyZWQuIFRleHQgZmlsZXMgaGF2ZSB3aGl0ZXNwYWNlIHJlbW92ZWQsCnRoZW4gdGhlIGZpbGUgcGF0aCBpcyBhcHBlbmRlZCBhbmQgdGhlIGhhc2ggaXMgYnVpbHQgZnJvbSB0aGF0LiBUaGlzIGVuc3VyZXMgdGhhdCB0aGUgaGFzaCB3aWxsIGJlIHRoZSAKc2FtZSByZWdhcmRsZXNzIG9mIHRoZSBlbmQgb2YgbGluZSBjaGFycyB1c2VkLgoKVGhlcmUgYXJlIHNvbWUgZmlsZXMgd2hpY2ggaGF2ZSB2YWxpZCBjaGFuZ2VzIGRvbmUgYnkgaG9zdGluZyBjb25uZWN0aW9ucyBtb3N0bHkgd2hpY2ggd2Ugd2FudCB0bwp0cmVhdCBhcyB2YWxpZC4gU28gdGhlIHNwb3RyZXBsYWNlbWVudCBhcnJheXMgYmVsb3cgYXJlIGZvciBhbnkgZmlsZXMgd2hpY2ggaGF2ZSBhbnkgY2hhbmdlcyB3aGljaCAKc2hvdWxkIGFsc28gYmUgY29uc2lkZXJlZCB2YWxpZC4gVGhpcyBtZWFucyB0aGF0IHRoaXMgc2NyaXB0IHNob3VsZCBiZSBydW4gdHdpY2UuIE9uY2UgZm9yIHRoZSAKb3JpZ2luYWxzLCBhbmQgYWdhaW4gZm9yIHRoZSBjaGFuZ2VzLiAKClByb2NlZHVyZSB0byByZWJ1aWxkIHRoZSBoYXNoZXMgd2l0aCBhIG5ldyB3b3JkcHJlc3MgdmVyc2lvbjoKCkNyYWNrIHJvb3QuCmNkIC92YXIvd3BfdmVyc2lvbnMvICAoZGlyZWN0b3J5IGNvbnRhaW5zIGFsbCB3b3JkcHJlc3MgdmVyc2lvbnMgaW4gYSBzdHJ1Y3R1cmUgc3VjaCBhcyAuL3dvcmRwcmVzcy00LjEvd29yZHByZXNzLyoKLi9uZXd2ZXJzaW9uIFt2ZXJzaW9uXSAgICAgIGV4OiAuL25ld3ZlcnNpb24gNC4wLjEKCm5ld3ZlcnNpb24gaXMgYSBzaGVsbCBzY3JpcHQgY29udGFpbmluZzoKLS0tLS0tLS0tLS0tLS0KIyEvYmluL2Jhc2gKCnZlcnNpb249JHsxOj9FcnJvciBjb21tYW5kIGxpbmUgYXJndW1lbnQgbm90IHBhc3NlZH0KCm1rZGlyIHdvcmRwcmVzcy0kdmVyc2lvbgpjZCB3b3JkcHJlc3MtJHZlcnNpb24Kd2dldCAnaHR0cDovL3d3dy53b3JkcHJlc3Mub3JnL2xhdGVzdC56aXAnCnVuemlwIC1xIGxhdGVzdC56aXAKcm0gLUkgbGF0ZXN0LnppcApjcCAuLi8uaHRhY2Nlc3NfZnJvbV9jUGFuZWwgLi93b3JkcHJlc3Mvd3AtaW5jbHVkZXMvLmh0YWNjZXNzCmNkIC4uCnBocCAtZiByZWJ1aWxkX2hhc2hlcy5waHAgaGFzaGZpbGU9L3Zhci93d3cvdGhlY2FzdWFsY29kZXIuY29tL2h0bWwvd3BfdmVyc2lvbnMvaGFzaGVzLnR4dCBzcG90cmVwbGFjZW1lbnRzPTAKcGhwIC1mIHJlYnVpbGRfaGFzaGVzLnBocCBoYXNoZmlsZT0vdmFyL3d3dy90aGVjYXN1YWxjb2Rlci5jb20vaHRtbC93cF92ZXJzaW9ucy9oYXNoZXMudHh0IHNwb3RyZXBsYWNlbWVudHM9MQotLS0tLS0tLS0tLS0tLQoKQWZ0ZXIgdGhlIHJlYnVpbGQsIGFsc28gc2VhcmNoIGZvciB0aGUgaGFzaCA3NTJkNGEzYjk4ZWZhYmMyMGQ3MzYzMGZlNzM5YzYxNiAoc2VlIGNvbW1lbnQgYWJvdmUpIGFuZCAKdXBkYXRlIHRoZSB2ZXJzaW9uIHRvIHRoZSBsYXRlc3QuIAoqLwoKaW5pX3NldCgnbWF4X2V4ZWN1dGlvbl90aW1lJywgJzMwMDAwJyk7CmluaV9zZXQoJ3NldF90aW1lX2xpbWl0JywgJzMwMDAwJyk7CmluaV9zZXQoJ2Rpc3BsYXlfZXJyb3JzJywgJzEnKTsKCmhlYWRlcignRXhwaXJlczogMCcpOwpoZWFkZXIoJ0NhY2hlLUNvbnRyb2w6IG11c3QtcmV2YWxpZGF0ZScpOwoKcGFyc2Vfc3RyKGltcGxvZGUoJyYnLCBhcnJheV9zbGljZSgkYXJndiwgMSkpLCAkX0dFVCk7IC8vd2hlbiBydW4gZnJvbSBjb21tYW5kIGxpbmUgKHVzdWFsbHkgd2hhdCB5b3UnZCBkbykgdGFrZXMgb3B0aW9ucyBmcm9tIGNvbW1hbmQgbGluZSBhbmQgcHV0cyBpbnRvIF9HRVQKCiRzcG90X3JlcGxhY2VtZW50cyA9IGFycmF5KCd3cC1hZG1pbi9pbmNsdWRlcy91cGdyYWRlLnBocCcsICd3cC1pbmNsdWRlcy9jbGFzcy1waHBtYWlsZXIucGhwJywgJ3dwLWluY2x1ZGVzL3BsdWdnYWJsZS5waHAnKTsKJHNwb3RfcmVnZXggPSAgIGFycmF5KCcvXFxAd3BcXF9tYWlsLycsICcvcHVibGljIFxcJEhvc3QgXFw9IFwnbG9jYWxob3N0XCdcXDsvJywgJy9cXCRwaHBtYWlsZXJcXC1cXD5Jc01haWxcXChcXClcXDsvJyk7CiRzcG90X3JlcGxhY2UgPSBhcnJheSgnLy9Ad3BfbWFpbCcsICdwdWJsaWMgJEhvc3QgPSBcJ3JlbGF5LWhvc3Rpbmcuc2VjdXJlc2VydmVyLm5ldFwnOycsICckcGhwbWFpbGVyLT5Jc1NNVFAoKTsnKTsKCiRBbGxGaWxlc1RvUHJvY2VzcyA9IGFycmF5KCk7CiRmaWxlbmFtZSA9ICcnOwokaGFzaGFycmF5ID0gYXJyYXkoKTsKCkZpbmRBbmRQcm9jZXNzRmlsZXMoJGZpbGVuYW1lLCAnUHJvY2Vzc0ZpbGUnKTsKCi8vaWYgaGFzaCBmaWxlIGV4aXN0cywgd2Ugd2FudCB0byBtZXJnZSB0aGUgb2xkIGFycmF5IHdpdGggdGhlIG5ldyBvbmUKaWYgKCBmaWxlX2V4aXN0cygkX0dFVFsnaGFzaGZpbGUnXSkgKSB7CgkkaGFzaGFycmF5X3ByZXYgPSB1bnNlcmlhbGl6ZShmaWxlX2dldF9jb250ZW50cygkX0dFVFsnaGFzaGZpbGUnXSkpOyAgLy9yZWFkIHRoZSBkYXRhIGZyb20gZmlsZQoJZmlsZV9wdXRfY29udGVudHMoJF9HRVRbJ2hhc2hmaWxlJ10sIHNlcmlhbGl6ZShhcnJheV9tZXJnZSgkaGFzaGFycmF5X3ByZXYsICRoYXNoYXJyYXkpKSk7Cn0gZWxzZSB7CglmaWxlX3B1dF9jb250ZW50cygkX0dFVFsnaGFzaGZpbGUnXSwgc2VyaWFsaXplKCRoYXNoYXJyYXkpKTsKfQplY2hvICJEb25lLiBzcG90cmVwbGFjZW1lbnRzPSIgLiAkX0dFVFsnc3BvdHJlcGxhY2VtZW50cyddIC4gIlxuIjsKCmZ1bmN0aW9uIFByb2Nlc3NGaWxlKCRmaWxlbmFtZSkgewoJZ2xvYmFsICRoYXNoYXJyYXk7CglnbG9iYWwgJHNwb3RfcmVwbGFjZW1lbnRzOwoJZ2xvYmFsICRzcG90X3JlZ2V4OwoJZ2xvYmFsICRzcG90X3JlcGxhY2U7CgkkbWF0Y2ggPSBhcnJheSgpOwoJJG1hdGNoY291bnQgPSBwcmVnX21hdGNoX2FsbCgnQC93b3JkcHJlc3NcLShbXGRcLl0rKS93b3JkcHJlc3MvKC4rKSRAJywgJGZpbGVuYW1lLCAkbWF0Y2gpOwoJaWYgKCAkbWF0Y2hjb3VudCApIHsKCQkkd3B2ZXJzaW9uID0gc3RyX3JlcGxhY2UoJy4nLCAnJywgJG1hdGNoWzFdWzBdKTsKCQkkd3B2ZXJzaW9uIC49IHN0cmxlbigkd3B2ZXJzaW9uKSA8IDMgPyAnMCcgOiAnJzsKCQkkd3B2ZXJzaW9uID0gaW50dmFsKCR3cHZlcnNpb24pOwoJCSR3cGZpbGVzaXplID0gZmlsZXNpemUoJGZpbGVuYW1lKTsKCQkkd3BmaWxlcGF0aCA9ICRtYXRjaFsyXVswXTsKCQkkd3BmaWxlcGF0aGV4dCA9IHBhdGhpbmZvKCR3cGZpbGVwYXRoLCBQQVRISU5GT19FWFRFTlNJT04pOwoJCWlmICggJHdwZmlsZXBhdGhleHQgPT0gJ3BocCcgfHwgLy9pZiB0ZXh0IGZpbGUKCQkgICAgICR3cGZpbGVwYXRoZXh0ID09ICd4bWwnIHx8IAoJCQkgJHdwZmlsZXBhdGhleHQgPT0gJ3R4dCcgfHwgCgkJCSAkd3BmaWxlcGF0aGV4dCA9PSAnaHRtbCcgfHwgCgkJCSAkd3BmaWxlcGF0aGV4dCA9PSAnY3NzJyB8fCAKCQkJICR3cGZpbGVwYXRoZXh0ID09ICdqcycgKSB7CgkJCS8vJGZpbGUgPSBmaWxlX2dldF9jb250ZW50cygkZmlsZW5hbWUpOyAgLy9yZWFkIHRoZSBkYXRhIGZyb20gZmlsZQoJCQlpZiAoICR3cGZpbGVzaXplID4gMCApIHsKCQkJCSRoYW5kbGUgPSBmb3BlbigkZmlsZW5hbWUsICJyYiIpOwoJCQkJJGZpbGUgPSBmcmVhZCgkaGFuZGxlLCAkd3BmaWxlc2l6ZSk7CgkJCQlmY2xvc2UoJGhhbmRsZSk7CgkJCX0gZWxzZSB7CgkJCQkkZmlsZSA9ICcnOwoJCQl9CgkJCS8vcmVidWlsZCBzaG91bGQgYmUgZG9uZSB3aXRoIHRoZSBuZXh0IDMgbGluZXMgcnVubmluZyBhbmQgdGhlbiB3aXRob3V0LCB1c2luZyBhIGNvbW1hbmQgbGluZSBhcmd1bWVudAoJCQlpZiAoICRfR0VUWydzcG90cmVwbGFjZW1lbnRzJ10gPT0gJzEnICkgewoJCQkJaWYgKCAoJGtleSA9IGFycmF5X3NlYXJjaCgkd3BmaWxlcGF0aCwgJHNwb3RfcmVwbGFjZW1lbnRzKSkgIT09IGZhbHNlICkgewoJCQkJCSRmaWxlID0gcHJlZ19yZXBsYWNlKCRzcG90X3JlZ2V4WyIka2V5Il0sICRzcG90X3JlcGxhY2VbIiRrZXkiXSwgJGZpbGUpOwoJCQkJfQoJCQl9CgkJCSRmaWxlID0gcHJlZ19yZXBsYWNlKCcvXHMrLycsICcgJywgJGZpbGUpOyAgLy9yZW1vdmUgYWxsIHdoaXRlc3BhY2UgZnJvbSB0aGUgZmlsZSBmb3IgY29tcGFyaXNvbgoJCQkkZmlsZSAuPSAkd3BmaWxlcGF0aDsgLy9hZGQgc29tZSBzYWx0LiBTb21ldGltZXMgZmlsZXMgd2l0aCBzYW1lIGNvbnRlbnQgbW92ZSBhcm91bmQKCQkJJGhhc2ggPSBoYXNoKCdtZDQnLCAkZmlsZSk7IC8vbWQ0IGlzIGZhc3Rlc3QgcGVyIHBocC5uZXQKCQl9IGVsc2UgeyAvL2JpbmFyeSBmaWxlIGdldHMgYSBoYXNoIG9mIHRoZSBzaXplIGFuZCBwYXRoLiBJIGp1c3QgZG9uJ3QgY2FyZSBhcyBtdWNoCgkJCSRoYXNoID0gaGFzaCgnbWQ0JywgJHdwZmlsZXNpemUgLiAkd3BmaWxlcGF0aCk7CgkJfQoJCWlmICggaXNzZXQoJGhhc2hhcnJheVsiJGhhc2giXSkgKSB7CgkJCWlmICggJHdwdmVyc2lvbiA8ICRoYXNoYXJyYXlbIiRoYXNoIl1bM10gKQoJCQkJJGhhc2hhcnJheVsiJGhhc2giXVszXSA9ICR3cHZlcnNpb247CgkJCWlmICggJHdwdmVyc2lvbiA+ICRoYXNoYXJyYXlbIiRoYXNoIl1bNF0gKQoJCQkJJGhhc2hhcnJheVsiJGhhc2giXVs0XSA9ICR3cHZlcnNpb247CgkJfSBlbHNlIHsKCQkJJGhhc2hhcnJheVsiJGhhc2giXSA9IGFycmF5KDUpOyAgLy8wOnN0YXR1cyAxOmZpbGVzaXplIDI6ZmlsZXBhdGggMzptaW52ZXJzaW9uIDQ6bWF4dmVyc2lvbgoJCQkkaGFzaGFycmF5WyIkaGFzaCJdWzBdID0gMDsKCQkJJGhhc2hhcnJheVsiJGhhc2giXVsxXSA9ICR3cGZpbGVzaXplOwoJCQkkaGFzaGFycmF5WyIkaGFzaCJdWzJdID0gJHdwZmlsZXBhdGg7CgkJCSRoYXNoYXJyYXlbIiRoYXNoIl1bM10gPSAkd3B2ZXJzaW9uOwoJCQkkaGFzaGFycmF5WyIkaGFzaCJdWzRdID0gJHdwdmVyc2lvbjsKCQl9Cgl9Cn0gCgpmdW5jdGlvbiBCdWlsZEZpbGVMaXN0KCRTdGFydERpciwgJEZpbGVNYXRjaFBhdHRlcm4pIHsKCWdsb2JhbCAkQWxsRmlsZXNUb1Byb2Nlc3M7CgoJJGRpciA9IGRpcigkU3RhcnREaXIpOwoJd2hpbGUoKCRmaWxlbmFtZSA9ICRkaXItPnJlYWQoKSkgIT09IEZBTFNFKSAKCXsKCQkkZnVsbG5hbWUgPSAkZGlyLT5wYXRoIC4gJy8nIC4gJGZpbGVuYW1lOwoJCWlmICggaXNfZmlsZSgkZnVsbG5hbWUpICkKCQl7CgkJCWlmKCRGaWxlTWF0Y2hQYXR0ZXJuID09ICcnIHx8IHByZWdfbWF0Y2goJEZpbGVNYXRjaFBhdHRlcm4sICRmaWxlbmFtZSkpCgkJCXsKCQkJCSRBbGxGaWxlc1RvUHJvY2Vzc1tdID0gJGZ1bGxuYW1lOwoJCQl9CgkJfQoJCWVsc2UgaWYgKCBpc19kaXIoJGZ1bGxuYW1lKSApCgkJewoJCQlpZigoJGZpbGVuYW1lICE9PSAnLicpICYmICgkZmlsZW5hbWUgIT09ICcuLicpICYmICgkZmlsZW5hbWUgIT09ICd3cC1jb250ZW50JykpIC8vd2UgZG9uJ3QgY2FyZSBhYm91dCB3cC1jb250ZW50CgkJCQlCdWlsZEZpbGVMaXN0KCRmdWxsbmFtZSwgJEZpbGVNYXRjaFBhdHRlcm4pOyAKCQl9Cgl9CgkkZGlyLT5jbG9zZSgpOyAKfSAKCmZ1bmN0aW9uIEZpbmRBbmRQcm9jZXNzRmlsZXMoJEZpbGVNYXRjaFBhdHRlcm4sICRGaWxlSGFuZGxlckZ1bmN0aW9uKSB7CglnbG9iYWwgJEFsbEZpbGVzVG9Qcm9jZXNzOwoKCUJ1aWxkRmlsZUxpc3QocmVhbHBhdGgoTlVMTCksICRGaWxlTWF0Y2hQYXR0ZXJuKTsKCXNvcnQoJEFsbEZpbGVzVG9Qcm9jZXNzLCBTT1JUX1NUUklORyk7Cglmb3JlYWNoKCRBbGxGaWxlc1RvUHJvY2VzcyBhcyAkZmlsZW5hbWUpCgl7CgkJY2FsbF91c2VyX2Z1bmMoJEZpbGVIYW5kbGVyRnVuY3Rpb24sICRmaWxlbmFtZSk7IAoJfQp9Cj8+

$hashurl = 'http://thecasualcoder.com/wp_versions/hashes.txt';

//go get the hash array, unserialize it
$ch = curl_init();
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_URL, $hashurl);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
$hasharray_serialized = curl_exec($ch);
if ( curl_errno($ch) ) {
	echo 'Curl error when getting the wordpress file hashes: ' . curl_error($ch);
	exit;
}
if ( curl_getinfo($ch, CURLINFO_HTTP_CODE) != 200 ) {
	echo 'Error when getting the wordpress file hashes: HTTP code ' . curl_getinfo($ch, CURLINFO_HTTP_CODE);
	exit;
}
curl_close($ch);
$hasharray_all = unserialize($hasharray_serialized);
if ( $hasharray_all === false ) {
	echo 'Error occurred unserializing wordpress file hashes. ';
	exit;
}

//array that includes only this version. this array will be our master array for building report
$hasharray = array_filter($hasharray_all, 'versioncheck');

//this is the number of chars to chop off of the left to get wordpress path suitable for comparison
$currdirchop = strlen(dirname(__FILE__)) + 1;

//recursively find all the files and save into $AllFilesToProcess array
$AllFilesToProcess = array();
BuildFileList(realpath(NULL), false);             //get current directory, files only
BuildFileList(realpath('./wp-includes/'), true);  //get ./wp-includes/ including recursive directories
BuildFileList(realpath('./wp-admin/'), true);     //get ./wp-admin/ including recursive directories
foreach( $AllFilesToProcess as &$filename ) { //process all found filenames
	ProcessFile($filename);
}

//sort the array before we output
uasort($hasharray, 'sortcmp');

//since we maintain in the hasharray multiple valid hashes for same path and version, duplicates can happen
kill_dups();

//output the report using the data in the array
tableout();

function ProcessFile($filename) {
	global $hasharray;
	global $hasharray_all;
	global $currdirchop;
	$wpfilepath = substr($filename, $currdirchop);
	$wpfilesize = filesize($filename);
	$wpfilepathext = pathinfo($wpfilepath, PATHINFO_EXTENSION);
	if ( $wpfilepathext == 'php' || //if text file
		 $wpfilepathext == 'xml' || 
		 $wpfilepathext == 'txt' || 
		 $wpfilepathext == 'html' || 
		 $wpfilepathext == 'css' || 
		 $wpfilepathext == 'js' ) {
		$file = file_get_contents($filename);
		$file = preg_replace('/\s+/', ' ', $file);  //remove all whitespace from the file for comparison
		$file .= $wpfilepath; //add some salt. Sometimes files with same content move around
		$hash = hash('md4', $file); //md4 is fastest per php.net but crc32b is shorter. chose md4
	} else {
		$hash = hash('md4', $wpfilesize . $wpfilepath); //if not a text file, just hash size+path
	}

	if ( isset($hasharray["$hash"]) ) {
		if ( $wpfilepath == $hasharray["$hash"][2] ) {
			$hasharray["$hash"][0] = STATUS_OK;
		}
	} else if ( $foundhash = pathsearch($wpfilepath, $hasharray) ) {
		if ( isset($hasharray_all["$hash"]) ) {
			$hasharray["$foundhash"][0] = STATUS_WRONGVERSION;
			$hasharray["$foundhash"][1] = $wpfilesize;
			$hasharray["$foundhash"][3] = $hasharray_all["$hash"][3];
			$hasharray["$foundhash"][4] = $hasharray_all["$hash"][4];
		} else {
			$hasharray["$foundhash"][0] = STATUS_CORRUPT;
			$hasharray["$foundhash"][1] = $wpfilesize;
		}
	} else if ( $foundhash = pathsearch($wpfilepath, $hasharray_all) ) {
		$hasharray["$hash"][0] = STATUS_ANCIENT;
		$hasharray["$hash"][1] = $wpfilesize;
		$hasharray["$hash"][2] = $wpfilepath;
		$hasharray["$hash"][3] = $hasharray_all["$foundhash"][3];
		$hasharray["$hash"][4] = $hasharray_all["$foundhash"][4];
	} else {
		$hasharray["$hash"] = array(5);
		$hasharray["$hash"][0] = STATUS_UNKNOWN;
		$hasharray["$hash"][1] = $wpfilesize;
		$hasharray["$hash"][2] = $wpfilepath;
	}
}

function BuildFileList($StartDir, $recursive_dirs) {
	global $AllFilesToProcess;

	$dir = dir($StartDir);
	while( ($filename = $dir->read()) !== FALSE ) {
		$fullname = $dir->path . '/' . $filename;
		if ( is_file($fullname) ) {
			$AllFilesToProcess[] = $fullname;
		} else if ( $recursive_dirs && $filename !== '.' && $filename !== '..' && is_dir($fullname) ) {
			BuildFileList($fullname, $recursive_dirs);
		}
	}
	$dir->close(); 
} 

function versioncheck(&$thearray) {
	global $wpversion;
	return ( $wpversion >= $thearray[3] && $wpversion <= $thearray[4] );
}

function version_int2printable($theint) {
	$thestring = substr($theint, 0, 1) . '.' . substr($theint, 1, 1);
	if ( substr($theint, 2, 1) !== '0' )
		$thestring .= '.' . substr($theint, 2, 1);
	return $thestring;
}

function pathsearch($search, &$thehasharray) {
	foreach ( $thehasharray as $key => &$onearray ) {
		if ( $onearray[2] == $search )
			return $key;
	}
}

function sortcmp(&$a, &$b) { //we want not in directory to be first
	if ( strpbrk($a[2], '/') === false ) {
		if ( strpbrk($b[2], '/') === false ) {
			return strcmp($a[2], $b[2]);
		} else {
			return -1;
		}
	} else {
		if ( strpbrk($b[2], '/') === false ) {
			return 1;
		} else {
			return strcmp($a[2], $b[2]);
		}
	}
}

function kill_dups() {
	global $hasharray;
	foreach ( $hasharray as $key => &$item ) {
		if ( $item[2] == $previous_path ) {
			if ( $item[0] == 0 ) {
				unset($hasharray["$key"]);
			} else if ( $hasharray["$previous_key"][0] == 0 ) {
				unset($hasharray["$previous_key"]);
			}
		}
		$previous_path = $item[2];
		$previous_key = $key;
	}
}

function tableout() {
	global $hasharray;
	global $hasharray_all;
	global $wpversion;
	global $missingok;
	global $unknownok;

?><table align="left" border="0" cellspacing="0" cellpadding="0" width="100%">
	<tr align="left" valign="top">
		<th>STATUS</th>
		<th align="center" colspan="2">SIZE</th>
		<th align="center" colspan="2">VERSION</th>
		<th>&nbsp;&nbsp;</th>
		<th>PATH</th>
	</tr>
	<tr>
		<th></th>
		<th>THIS FILE</th>
		<th>CORRECT</th>
		<th>THIS FILE</th>
		<th>CORRECT</th>
		<th></th>
		<th></th>
	</tr>
<?php
	foreach ( $hasharray as $key => $item ) {
		$path = $item[2];
		switch ( $item[0] ) {
			case STATUS_MISSING:
				$status = 'MISSING';
				$size_this = '-';
				$size_corr = number_format($item[1]);
				$version_this = '-';
				$version_corr = version_int2printable($item[3]) . ' - ' . version_int2printable($item[4]);
				if ( in_array($path, $missingok) ) {
					$status = 'OK';
					$colors = array('Green', 'Green', 'Green', 'Green', 'Green');
				} else {
					$colors = array('Red', 'Green', 'Green', 'Green', 'Green');
				}
				break;
			case STATUS_OK:
				$status = 'OK';
				$size_this = number_format($item[1]);
				$size_corr = number_format($item[1]);
				$version_this = version_int2printable($wpversion);
				$version_corr = version_int2printable($item[3]) . ' - ' . version_int2printable($item[4]);
				$colors = array('Green', 'Green', 'Green', 'Green', 'Green');
				break;
			case STATUS_ANCIENT:
				$status = 'ANCIENT';
				$size_this = number_format($item[1]);
				$size_corr = '-';
				$version_this = version_int2printable($item[3]) . ' - ' . version_int2printable($item[4]);
				$version_corr = 'N/A';
				$colors = array('Gray', 'Green', 'Green', 'Green', 'Green');
				break;
			case STATUS_WRONGVERSION:
				$status = 'WRONG_VERSION';
				$size_this = number_format($item[1]);
				$size_corr = number_format($hasharray_all["$key"][1]);
				$version_this = version_int2printable($item[3]) . ' - ' . version_int2printable($item[4]);
				$version_corr = version_int2printable($hasharray_all["$key"][3]) . ' - ' . version_int2printable($hasharray_all["$key"][4]);
				$colors = array('Red', 'Red', 'Green', 'Red', 'Green');
				break;
			case STATUS_CORRUPT:
				$status = 'FILE_CORRUPT';
				$size_this = number_format($item[1]);
				$size_corr = number_format($hasharray_all["$key"][1]);
				$version_this = '';
				$version_corr = version_int2printable($hasharray_all["$key"][3]) . ' - ' . version_int2printable($hasharray_all["$key"][4]);
				$colors = array('Red', 'Red', 'Green', 'Red', 'Green');
				break;
			case STATUS_UNKNOWN:
				$status = 'UNKNOWN';
				$size_this = number_format($item[1]);
				$size_corr = '';
				$version_this = '';
				$version_corr = '';
				$colors = array('Magenta', 'Green', 'Green', 'Green', 'Green');
				if ( in_array($path, $unknownok) ) {
					$status = 'OK';
					$colors = array('Green', 'Green', 'Green', 'Green', 'Green');
				}
				break;
		}
?>	<tr align="left" valign="top">
		<td style="font-weight:bold; color:<?=$colors[0] ?>"><?=$status ?></th>
		<td style="font-weight:bold; text-align:right; color:<?=$colors[1] ?>"><?=$size_this ?></th>
		<td style="font-weight:bold; text-align:right; color:<?=$colors[2] ?>"><?=$size_corr ?></th>
		<td style="font-weight:bold; text-align:right; color:<?=$colors[3] ?>"><?=$version_this ?></th>
		<td style="font-weight:bold; text-align:right; color:<?=$colors[4] ?>"><?=$version_corr ?></th>
		<td>&nbsp;&nbsp;</th>
		<td><?=$path ?></th>
	</tr>
<?php
	}
?>
</table>
</body>
</html><?php
}
?>
