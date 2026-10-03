<?php
/**
 * Plugin Name: ALV Sniffer (Phase 0 diagnostic)
 * Description: Throwaway tool. Logs outbound HTTP calls to candidate vendor hosts
 *              so we can see how Bricks/Oxygen validate licenses and fetch updates.
 *              Logs metadata only — never header or body VALUES. Remove after Phase 0.
 * Version:     0.1.0
 * Author:      DPlugins
 *
 * INSTALL: copy this file into wp-content/mu-plugins/ on the TEST site only.
 * It activates automatically (mu-plugins have no activation step).
 *
 * This plugin is read-only: it observes requests and passes them through
 * untouched. It never blocks, rewrites, or relays anything.
 *
 * @package AlvSniffer
 */

namespace DPlugins\LicenseVault\Sniffer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hosts we care about. Add any you spot in the log that look vendor-related,
 * then re-run the capture. Matching is substring-on-host, case-insensitive.
 */
const WATCH_HOSTS = array(
	'bricksbuilder.io',
	'bricks',          // catches licensing subdomains
	'oxygenbuilder.com',
	'soflyy.com',      // Oxygen's vendor
	'wpoxygen',
);

/**
 * Keys whose VALUES must never be written to the log, even partially.
 * We record that the key was present, not what it held.
 */
const SECRET_KEYS = array(
	'license', 'license_key', 'licensekey', 'key', 'api_key', 'apikey',
	'token', 'secret', 'activation', 'password', 'pass', 'auth',
);

/**
 * Resolve the log path. Prefer a location OUTSIDE the web root.
 * Falls back to wp-content if the parent isn't writable, with a warning line.
 */
function log_path(): string {
	$candidate = dirname( ABSPATH ) . '/alv-sniffer.log'; // one level above web root
	$dir       = dirname( $candidate );

	if ( is_writable( $dir ) ) {
		return $candidate;
	}

	// Fallback: inside wp-content. Less ideal, but still metadata-only.
	return WP_CONTENT_DIR . '/alv-sniffer.log';
}

/**
 * Does this URL point at a watched vendor host?
 */
function is_watched( string $url ): bool {
	$host = wp_parse_url( $url, PHP_URL_HOST );
	if ( ! is_string( $host ) || '' === $host ) {
		return false;
	}
	$host = strtolower( $host );
	foreach ( WATCH_HOSTS as $needle ) {
		if ( false !== strpos( $host, strtolower( $needle ) ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Reduce a value to a safe descriptor: type and length, never content.
 */
function describe( $value ): string {
	if ( is_array( $value ) ) {
		return 'array(' . count( $value ) . ')';
	}
	if ( is_string( $value ) ) {
		return 'string(' . strlen( $value ) . ')';
	}
	if ( is_bool( $value ) ) {
		return $value ? 'bool(true)' : 'bool(false)';
	}
	if ( is_scalar( $value ) ) {
		return gettype( $value );
	}
	return gettype( $value );
}

/**
 * Turn an associative set of fields into "name=descriptor" pairs, masking
 * any field whose name looks secret.
 */
function summarize_fields( array $fields ): array {
	$out = array();
	foreach ( $fields as $name => $value ) {
		$lower  = is_string( $name ) ? strtolower( $name ) : (string) $name;
		$masked = false;
		foreach ( SECRET_KEYS as $secret ) {
			if ( false !== strpos( $lower, $secret ) ) {
				$masked = true;
				break;
			}
		}
		$out[] = $name . '=' . ( $masked ? 'PRESENT(masked)' : describe( $value ) );
	}
	return $out;
}

/**
 * Best-effort parse of a request body into field names only.
 * Handles query-string and JSON bodies; otherwise reports the raw length.
 */
function summarize_body( $body ): array {
	if ( empty( $body ) ) {
		return array( '(empty body)' );
	}
	if ( is_array( $body ) ) {
		return summarize_fields( $body );
	}
	if ( is_string( $body ) ) {
		$trimmed = ltrim( $body );
		if ( '' !== $trimmed && ( '{' === $trimmed[0] || '[' === $trimmed[0] ) ) {
			$decoded = json_decode( $body, true );
			if ( is_array( $decoded ) ) {
				return array_merge( array( '(json body)' ), summarize_fields( $decoded ) );
			}
		}
		parse_str( $body, $parsed );
		if ( ! empty( $parsed ) ) {
			return array_merge( array( '(form body)' ), summarize_fields( $parsed ) );
		}
		return array( 'raw string(' . strlen( $body ) . ')' );
	}
	return array( describe( $body ) );
}

/**
 * Append one record to the log. Never throws.
 */
function write_log( array $record ): void {
	$line = '[' . gmdate( 'Y-m-d H:i:s' ) . "Z]\n";
	foreach ( $record as $label => $value ) {
		if ( is_array( $value ) ) {
			$line .= '  ' . $label . ":\n";
			foreach ( $value as $item ) {
				$line .= '    - ' . $item . "\n";
			}
		} else {
			$line .= '  ' . $label . ': ' . $value . "\n";
		}
	}
	$line .= str_repeat( '-', 60 ) . "\n";

	// Silence errors: diagnostics must never break the host site.
	@file_put_contents( log_path(), $line, FILE_APPEND | LOCK_EX ); // phpcs:ignore
}

/**
 * Observe every outbound request via pre_http_request.
 * We DO NOT short-circuit: return false so WordPress performs the request normally.
 *
 * @param false|array|\WP_Error $preempt Short-circuit value. Always returned as-is.
 * @param array                 $args    Request args.
 * @param string                $url     Request URL.
 * @return false|array|\WP_Error
 */
function observe_request( $preempt, $args, $url ) {
	if ( is_string( $url ) && is_watched( $url ) ) {
		$headers = isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : array();
		write_log(
			array(
				'event'        => 'pre_http_request',
				'method'       => isset( $args['method'] ) ? strtoupper( (string) $args['method'] ) : 'GET',
				'url'          => esc_url_raw( $url ),
				'header names' => array_keys( $headers ),
				'body fields'  => summarize_body( $args['body'] ?? null ),
			)
		);
	}
	return $preempt;
}

/**
 * Observe completed requests via http_api_debug to capture response status
 * and header names (not values).
 *
 * @param array|\WP_Error $response Response or error.
 * @param string          $context  Context ('response').
 * @param string          $class    Transport class.
 * @param array           $args     Request args.
 * @param string          $url      Request URL.
 */
function observe_response( $response, $context, $class, $args, $url ): void {
	if ( ! is_string( $url ) || ! is_watched( $url ) ) {
		return;
	}

	if ( is_wp_error( $response ) ) {
		write_log(
			array(
				'event' => 'http_api_debug (error)',
				'url'   => esc_url_raw( $url ),
				'error' => $response->get_error_message(),
			)
		);
		return;
	}

	$code    = wp_remote_retrieve_response_code( $response );
	$headers = wp_remote_retrieve_headers( $response );
	$names   = array();
	if ( $headers ) {
		// WpOrg\Requests\Utility\CaseInsensitiveDictionary or array.
		foreach ( (array) ( method_exists( $headers, 'getAll' ) ? $headers->getAll() : $headers ) as $name => $value ) {
			$names[] = (string) $name;
		}
	}

	write_log(
		array(
			'event'              => 'http_api_debug (response)',
			'url'                => esc_url_raw( $url ),
			'status'             => (string) $code,
			'response header names' => $names,
			'body length'        => describe( wp_remote_retrieve_body( $response ) ),
		)
	);
}

add_filter( 'pre_http_request', __NAMESPACE__ . '\\observe_request', 1, 3 );
add_action( 'http_api_debug', __NAMESPACE__ . '\\observe_response', 1, 5 );

// One-time banner so you can confirm the sniffer is live and where it logs.
add_action(
	'admin_notices',
	static function () {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<div class="notice notice-info"><p><strong>ALV Sniffer active.</strong> Logging vendor HTTP metadata to <code>'
			. esc_html( log_path() ) . '</code>. Remove this mu-plugin after Phase 0.</p></div>';
	}
);
