<?php
/*
Plugin Name: Log Login - LTC Custom
Plugin URI: https://github.com/PhilHagen/log-login
Description: Plugin to log logon attempts to YOURLS. Refer to <a href="https://github.com/PhilHagen/log-login">my page</a> for more details.  Modified from <a href="https://github.com/SweBarre/log-login">Jonas Forsberg's plugin</a> to use syslog rather than pear-Log and a more detailed log format.
Version: 0.3ltc
Author: Jonas Forsberg, Phil Hagen
Author URI: http://gargamel.nu/, http://lewestech.com/
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/* Add default settings

The following definitions can be overrided if they are defined in
the user/config.php
*/
if( !defined( 'BARRE_LOG_LOGIN_SUCCESS' )) define( 'BARRE_LOG_LOGIN_SUCCESS', false );
if( !defined( 'BARRE_LOG_LOGIN_FAILURE' )) define( 'BARRE_LOG_LOGIN_FAILURE', true );
if( !defined( 'BARRE_LOG_LOGIN_LOGOFF' )) define ( 'BARRE_LOG_LOGIN_LOGOFF', false);
if( !defined( 'BARRE_LOG_LOGIN_FILENAME' )) define ( 'BARRE_LOG_LOGIN_FILENAME', dirname( __FILE__) . DIRECTORY_SEPARATOR . 'logins.log');
if( !defined( 'BARRE_LOG_LOGIN_FILE' )) define ( 'BARRE_LOG_LOGIN_FILE', true );
if( !defined( 'BARRE_LOG_LOGIN_SYSLOG' )) define ( 'BARRE_LOG_LOGIN_SYSLOG', false );
if( !defined( 'BARRE_LOG_LOGIN_SYSLOG_FACILITY' )) define ( 'BARRE_LOG_LOGIN_SYSLOG_FACILITY', LOG_AUTHPRIV );
if( !defined( 'BARRE_LOG_LOGIN_SYSLOG_SEVERITY' )) define ( 'BARRE_LOG_LOGIN_SYSLOG_SEVERITY', LOG_NOTICE );

// register the action functions
if( BARRE_LOG_LOGIN_SUCCESS ) yourls_add_action( 'login', 'barre_log_login_success' );
if( BARRE_LOG_LOGIN_FAILURE ) yourls_add_action( 'login_failed', 'barre_log_login_failure' );
if( BARRE_LOG_LOGIN_LOGOFF ) yourls_add_action( 'logout', 'barre_log_login_logoff' );

// set log messages for each event
define( 'LOG_MESSAGE_SUCCESS', 'Success' );
define( 'LOG_MESSAGE_FAILED', 'Failed' );
define( 'LOG_MESSAGE_LOGOFF', 'Logoff' );

if ( BARRE_LOG_LOGIN_FILE ) {
    // Load the Log facility
    require_once('Log.php');
}

// The logging function for syslog logging
function barre_log_login_log2syslog ( $barre_log_login_result ) {
    if ( $barre_log_login_result == LOG_MESSAGE_FAILED ) {
        $remote_user = $_REQUEST['username'];
    } elseif ( $barre_log_login_result == LOG_MESSAGE_SUCCESS ) {
        $remote_user = YOURLS_USER;
    } else {
        // unfortunately, there is no variable with the username that is logging out at this hook location
        $remote_user = 'Undefined';
    }

    /* set the format of the log message
     * if you change this you probably have to change the
     * fail2ban regexp in the yourls filter
     */
    if ( $barre_log_login_result == LOG_MESSAGE_LOGOFF ) {
        $logstring = sprintf( 'YOURLS user event: %s from %s -> %s', $_SERVER['SERVER_NAME'], $_SERVER['REMOTE_ADDR'], $barre_log_login_result );
    } else {
        $logstring = sprintf( 'YOURLS user event: %s@%s from %s -> %s', $remote_user, $_SERVER['SERVER_NAME'], $_SERVER['REMOTE_ADDR'], $barre_log_login_result );
    }

    syslog( BARRE_LOG_LOGIN_SYSLOG_SEVERITY | BARRE_LOG_LOGIN_SYSLOG_FACILITY, $logstring );
}

// The logging function for direct-to-file logging
function barre_log_login_log2file( $barre_log_login_result ) {

    //check to see if the loffilename isn't set
    if( !defined( 'BARRE_LOG_LOGIN_FILENAME' )) {
        error_log( 'logfile name not configured' );
        return;
    }

    //Check to see if file doesn't exist OR if it's not writeble
    if( !is_writeable( BARRE_LOG_LOGIN_FILENAME  ) ) {
        // OK, something is wrong with the logfile
        // let's check if it exists and is not writeable
        if( file_exists( BARRE_LOG_LOGIN_FILENAME )) {
            //The file exists but not writeable, let's log an error and return from function
                    $message = 'The logfile is not writable: ' . BARRE_LOG_LOGIN_FILENAME;
                    error_log( $message );
            return;
        }
        // The file doesn't exist, let check if the folder is writeable
        if ( is_writeable( dirname( BARRE_LOG_LOGIN_FILENAME ))) {
            // lets create the logfile
            touch( BARRE_LOG_LOGIN_FILENAME );
            chmod( BARRE_LOG_LOGIN_FILENAME, 0600 );
        } else {
            //The logfile doesn't exist and the folder is not writeable
            // Let's log an error and return from function
                        $message = 'The folder for the logfile destination is not writable: ' . dirname( BARRE_LOG_LOGIN_FILENAME );
                        error_log( $message );
            return;
        }
    }

    if ( $barre_log_login_result == LOG_MESSAGE_FAILED ) {
        $remote_user = $_REQUEST['username'];
    } elseif ( $barre_log_login_result == LOG_MESSAGE_SUCCESS ) {
        $remote_user = YOURLS_USER;
    } else {
        // unfortunately, there is no variable with the username that is logging out at this hook location
        $remote_user = 'Undefined';
    }

    /* set the format of the log file
     * if you change this you probably have to change the
     * fail2ban regexp in the yourls filter
     */
    if ( $barre_log_login_result == LOG_MESSAGE_LOGOUT ) {
        $barre_login_log_conf = array(
            'lineFormat' => "%{timestamp} YOURLS user event: ".$_SERVER['SERVER_NAME']." from ".$_SERVER['REMOTE_ADDR']." -> %{message}",
            'timeFormat' => "%FT%T%z");
    } else {
        $barre_login_log_conf = array(
            'lineFormat' => "%{timestamp} YOURLS user event: ".YOURLS_USER."@".$_SERVER['SERVER_NAME']." from ".$_SERVER['REMOTE_ADDR']." -> %{message}",
            'timeFormat' => "%FT%T%z");
    }

    // Create a singleton log class
    $barre_login_log_file = Log::singleton('file', BARRE_LOG_LOGIN_FILENAME, 'BARRE_LOG_LOGIN_LOG', $barre_login_log_conf);
    //log to the file
    $barre_login_log_file->log( $barre_log_login_result );
}

//Log the successful logins
function barre_log_login_success() {
    //only log successful logins if the cookie isn't set
    if( !yourls_check_auth_cookie()) {
        if ( BARRE_LOG_LOGIN_FILE ) {
            barre_log_login_log2file( LOG_MESSAGE_SUCCESS );
        } 
        if ( BARRE_LOG_LOGIN_SYSLOG ) {
            barre_log_login_log2syslog( LOG_MESSAGE_SUCCESS );
        }
    }
}

//log the failed logins
function barre_log_login_failure() {
    if ( BARRE_LOG_LOGIN_FILE ) {
        barre_log_login_log2file( LOG_MESSAGE_FAILED );
    } 
    if ( BARRE_LOG_LOGIN_SYSLOG ) {
        barre_log_login_log2syslog( LOG_MESSAGE_FAILED );
    }
}

//log the logoffs
function barre_log_login_logoff() {
    if ( BARRE_LOG_LOGIN_FILE ) {
        barre_log_login_log2file( LOG_MESSAGE_LOGOFF );
    } 
    if ( BARRE_LOG_LOGIN_SYSLOG ) {
        barre_log_login_log2syslog( LOG_MESSAGE_LOGOFF );
    }
}
