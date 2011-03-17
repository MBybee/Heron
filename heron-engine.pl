#!/usr/bin/perl

#/****************************************************************************/
#/*                                                                         **/
#/*                             heron-engine                                **/
#/*                        Usage: heron-engine.pl                           **/
#/*                                                                         **/
#/*   This program is the backend for a server and database inventorty app  **/
#/*                                                                         **/
#/*                                                                         **/
#/*                                                                         **/
#/*                            Version: 0.5                                 **/
#/*   All code and graphics © Copyright 2005-2011 Mike Bybee.               **/
#/*                        All rights reserved                              **/
#/* Redistribution and use in source and binary forms, with or without      **/
#/* modification, are permitted provided that the following conditions are  **/
#/* met:                                                                    **/
#/*                                                                         **/
#/* * Redistributions of source code must retain the above copyright notice,**/
#/*   this list of conditions and the following disclaimer.                 **/
#/* * Redistributions in binary form must reproduce the above copyright     **/
#/*   notice, this list of conditions and the following disclaimer in the   **/
#/*   documentation and/or other materials provided with the distribution.  **/
#/* * Neither the name of the organization nor the names of its contributors**/
#/*   may be used to endorse or promote products derived from this software **/
#/*   without specific prior written permission.                            **/
#/*                                                                         **/
#/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     **/
#/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       **/
#/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A **/
#/* PARTICULAR PURPOSE ARE DISCLAIMED.                                      **/
#/* IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY**/
#/* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      **/
#/* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS **/
#/* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)   **/
#/* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,     **/
#/* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN**/
#/* ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE         **/
#/* POSSIBILITY OF SUCH DAMAGE.                                             **/
#/*                                                                         **/
#/*                You may obtain a copy of the License at:                 **/
#/*                 http://mbybee.net/bsdapps/LICENSE.html                  **/
#/*                                                                         **/
#/****************************************************************************/

#/****************************************************************************/
#/* Known Issues/TODO:                                                      **/
#/* * Optimize. There is always room for speed improvements.                **/
#/* * Several oddities and quirks - look for notes.                         **/
#/* * Redundant variables in several places due to 'fast and loose' POC     **/
#/* * Finish putting in the config file stuff, including the encryption     **/
#/* * Decide whether or not to keep the direct DB hooks here, or broken out **/
#/* * Fill out the correct schemas                                          **/
#/* * Fix the schema detection/creation steps for Oracle and DB2            **/
#/* * Add MS SQL support. The lack of a good, simple, free driver is a PITA **/
#/* * Find better, portable, still secure encryption                        **/
#/* * Not all database types support boolean. We'll do true=1 false=0       **/
#/* * Crypto is done with the cryptkey + a user-provided password hash.     **/
#/*   There are other, better crypto libs -they didn't seem portable enough.**/
#/* * Improve handling of remote system authentication.                     **/
#/* * The 'decom' function just sets live and audit to 0. Should we delete? **/
#/* * I used a few chunks of code a lot (like host selection) - break out?  **/
#/* * I don't check to see if a host has dependencies when decom'd. Add?    **/
#/* * Only supporting XML right now. Add JSON and such                      **/
#/* * I think the batch and cli record handling need to be consolidated     **/
#/****************************************************************************/


use strict;

# Note - 0 means a const is switched off, 1 means switched on
# Optional modules will be switched on or off with constants
# This was done because not all installs can use all modules
# Variables with a 'g' prefix are global. All caps are constants.

# Note - if you *increase* the max tablespaces via the config or default, it 
# will add more columns to the tables. It will not, however, drop columns.


use POSIX;
use Getopt::Long;
use XML::Simple;
# Optional use Crypt::CBC;
# Optional use Crypt::Blowfish;
# Optional use DBI;
# Optional use DBD::Oracle;
# Optional use DBD::SQLite;
# Optional use DBD::DB2;
# Optional use Parallel::ForkManager;
# Optional use JSON;
use constant DEBUG     => 1;
use constant TIMING    => 1;
use constant SUCCEEDED => 0;
use constant FAILED    => -1;
use constant CRYPTO    => 0;
use constant DB        => 1;
use constant PARALLEL  => 0;
use constant VERSION   => 1;
use constant CRYPTKEY  => '1Jajdi383pfly@eLD#K!$s.dua_*I3[kks993sjhndl\qurpo1pvhh5#ule,01@=39';
use Data::Dumper;


my $gcVersion = "Heron-Engine Version 0.02\nCopyright (c) 2005-2010, Mike Bybee All rights reserved. \nReleased under the terms of the BSD-Simplified license at \nhttp://mbybee.net/bsdapps/LICENSE.html\n";
my $gcHelp = "Usage: heron-engine.pl [option] \nExamples: --version, --verbose, --help, --configure, --check <method>, --server <servername>, --database <dbname>\n";
my @gaMessages;
my $gcRC;
my $gcLoop = 0;
my $gcCfgFile = "heron.cfg";
my $gDBH;
my $gcCipher;
my $gStart;
if( TIMING == 1 ){ $gStart = time; }
my $gXMLopt = XML::Simple->new(RootName=>'opt');
my @gChecks = ( "disk", "tablespace", "status" );

# These are the default options (also shows the format the options are in)
# TODO: Port the MSSQL specific crap like the DecryptByKey()
my %ghConfig = (
    "def"     => (    
        { 
            "intdbname"    => "heron.sqlite",
            "intdbuser"    => "",
            "intdbpass"    => "",
            "intdb"        => "sqlite",
            "outformat"    => "xml",
            "heronversion" => "1.0",
            "maxtspaces"   => 10,
            "maxbtcrec"    => 2,
            "usingdef"     => 1
        }
    ),
    "opt"     => (
        {
            "null"         => "null"
        }
    ),
    "sql"     => (
        {
            "intShortHostInf"    => ' hkey, hostname, ip, virtual, cluster, os from host_info',
            "intShortHostInf_OLD"    => ' hostid, hostname, ipaddress, virtual, cluster, os from host_info',
            "intShortUserInf"    => ' u.connect_string, u.dbname, userid, sysadmin, rdbms from user_info u, db_info d where d.connect_string = u.connect_string',
            "intShortDBInf"      => ' dkey, hkey, cluster, rdbms, dbver, app, dbname, production, owner from db_info',
            "intShortDBInf_OLD"      => ' dbid, hostname, cluster, rdbms, dbver, app, dbname, production, appowner from db_info',
            "intShortSoxInf"     => ' hostname, connect_string, dbname, username from sox_admin_users',
            "intShortSpaceInf"   => ' dbid, hostname, dbname, cluster, dbsize, logsize, lastupdate from db_info',
            "intHostandDBInf"    => ' hostid, h.hostname, ipaddress, virtual, h.cluster, rdbms, dbver, dbname, app, production from host_info h, db_info d where h.hostname = d.hostname',
            "intAllHostInf"      => ' hostid, hostname, ipaddress, virtual, cluster, os, ramgb, sanattached, osinfo from host_info',
            "intAllHostAndDBInf" => ' hostid, h.hostname, ipaddress, virtual, h.cluster, os, ramgb, sanattached, osinfo, rdbms, dbver, dbname, app, production from host_info h, db_info d where h.hostname = d.hostname',
            "infAllUserInf"      => ' u.dbname, u.connect_string, userid, username, ntlogin, ntgroup, default_user, sysadmin, create_date, rdbms, sox from user_info u, db_info d where d.connect_string = u.connect_string',
            "intAllDBInf"        => ' dbid, hostname, cluster, rdbms, app, appowner, dbver, dbver_edition, dbinstance, dbname, dbsize, logsize, production, lastupdate, backupfrequency from db_info',
            "intOraOnly"         => 'Select hostname, cluster, rdbms, dbver, dbinstance, app, production, appowner from db_info where rdbms like \'%ORACLE%\'',
            "intMSSQLOnly"       => 'Select hostname, cluster, rdbms, dbver, dbname, app, production, appowner from db_info where rdbms like \'%SQL%\'',
            "intMSSQLOnlySec"    => 'Select hostname, cluster, rdbms, dbver, dbname, app, production, appowner, convert(varchar(max), DecryptByKey(adminpass)), convert(varchar(max), DecryptByKey(comments)) from db_info where rdbms like \'%SQL%\'',
            "intOraOnlySec"      => 'Select hostname, cluster, rdbms, dbver, instance, app, production, appowner, convert(varchar(max), DecryptByKey(adminpass)), convert(varchar(max), DecryptByKey(comments)) from db_info where rdbms like \'%ORACLE%\'',
            "intBasicDBInfSec"   => 'Select hostname, cluster, rdbms, dbver, app, production, appowner, convert(varchar(max), DecryptByKey(adminpass)), convert(varchar(max), DecryptByKey(comments)) from db_info',
            "intHostAndDBInfSec" => 'Select h.hostname, ipaddress, virtual, h.cluster, rdbms, dbver, app, production, convert(varchar(max), DecryptByKey(adminpass)), convert(varchar(max), DecryptByKey(comments))  from host_info h, db_info d where h.hostname = d.hostname',
            "intUsersInf"        => 'Select connect_string, dbname, userid, sysadmin from user_info order by connect_string',
            "intHostOnly"        => 'select hostname from host_info',
            "intDBOnly"          => 'select distinct(rdbms) from db_info',
            "intConnOnly"        => 'select distinct(connect_string) from db_info',
            "intMSSQLConnOnly"   => 'select distinct(connect_string) from db_info where rdbms = \'MSSQL\'',
            "intOraConnOnly"     => 'select distinct(connect_string) from db_info where rdbms = \'ORACLE\' and dbinstance not like \'+ASM%\'',
            "intChangeInf"       => 'select ckey, skey, gkey, status, mod_rec, add_rec, del_rec, chstring, retval from changes order by ckey', 
            "intChangeNext"      => 'select ckey, status, loc, chstring from changes c, gui_key g where c.mod_rec <= g.mod_rec and c.add_rec <= g.add_rec and c.del_rec <= g.del_rec and c.status = \'new\' order by ckey',
            "intChangeActive"    => 'update changes set status = \'active\'',
            "intChangeComplete"  => 'update changes set status = \'complete\'',
            "intMSSQLGetConnStr" => 'select connect_string from db_info where rdbms = \'MSSQL\' group by connect_string, rdbms order by connect_string',
            "extMSSQL_DBInf"     => 'select serverproperty(\'productversion\') version, serverproperty(\'productlevel\') level, serverproperty(\'edition\') edition',
            "extMSSQL_DBVer"     => 'select serverproperty(\'productversion\')',
            "extMSSQL_DBVerLvl"  => 'select serverproperty(\'productlevel\')',
            "extMSSQL_DBVerEd"   => 'select serverproperty(\'edition\')',
            "extMSSQL_DBHum"     => 'select @@version version',
            "extMSSQL_UserData"  => 'select dbname, name, loginname, createdate, sysadmin, isntgroup, isntname from syslogins',
            "extOra_DBHum"       => 'select banner from v$version v where v.banner like \'%Oracle%\'',
            "extOra_UserData"    => 'select username, created, (select count(grantee) from dba_role_privs p where p.grantee = d.username and granted_role = \'DBA\') \'sysadmin\'  from dba_users d',
            "extOra_DBInf"       => 'select distinct instance_name, version, (select sum(bytes)/1024 from dba_data_files) dbsize, (select sum (bytes)/1024 from v$log) logsize, banner edition, (select sum(bytes)/1024000 from dba_free_space) freespace, s.bytes/1024000 leastfree from v\$instance i, v\$version v, (select tablespace_name, bytes from dba_free_space order by bytes ) s where v.banner like \'%Oracle%\' and rownum = 1'
        }
    )
);


# Initialize App
# NOTE: this may result in loading additional modules, like DBD::Oracle 
if( Init() == FAILED ){ Fail_Out( "Error initializing" ); }

# Take special actions based on args
if( DEBUG == 1 ){ printf( "Processing Arguments\n" ); }
if( $ghConfig{'arg'}{'configure'} == 1 ){
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Entering Config Mode\n\n\n" ); };
    Configure();
}
if( defined($ghConfig{'arg'}{'batch'}) ){
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Entering Batch Mode\n\n\n" ); };
    Run_Batch();
}
if( defined($ghConfig{'arg'}{'web'}) ){
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Entering Web Mode\n\n\n" ); };
    Run_Web();
}
if( $ghConfig{'arg'}{'check'} ){
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Checking $ghConfig{'arg'}{'check'}\n"); }
    # TODO: Add item-only checks
}
if( $ghConfig{'arg'}{'server'} ){
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Checking $ghConfig{'arg'}{'server'}\n"); }
    # TODO: Add server-only checks
}
if( $ghConfig{'arg'}{'database'} ){
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Checking $ghConfig{'arg'}{'database'}\n"); }
    # TODO: Add database-only checks
}


if( DEBUG == 1 ){ printf( "Done\n" ); }
exit( SUCCEEDED );


#/****************************************************************************/
#/* Read config, open DB connections, etc                                   **/
#/****************************************************************************/
sub Init{
    # Get_Config will load any needed modules, as well as setting up the hash
    if( Get_Config() == FAILED ){
        printf("Error reading config, using defaults.\n");
    }

    # Assign $gDBH appropriately, prepare the database if required
    if( DEBUG == 1 ){ printf( "Opening DB connection\n" ); }
    if( lc($ghConfig{'opt'}{'intdb'}) eq 'sqlite' ){
        if( Init_SQLite() == FAILED ){
            Fail_Out("Error handling internal SQLite DB.");
        }
        else{
            $ghConfig{'opt'}{'intdbok'} = 1;
            $ghConfig{'opt'}{'introws'} = " limit "; 
        }
    }
    elsif( lc($ghConfig{'opt'}{'intdb'}) eq 'oracle' ){
        if( Init_Oracle() == FAILED ){
            Fail_Out("Error handling internal Oracle DB.");
        }
        else{
            $ghConfig{'opt'}{'intdbok'} = 1;
            $ghConfig{'opt'}{'introws'} = " where rownum < "; 
        }
    }
    elsif( lc($ghConfig{'opt'}{'intdb'}) eq 'db2' ){
        if( Init_DB2() == FAILED ){
            Fail_Out("Error handling internal DB2 DB.");
        }
        else{
            $ghConfig{'opt'}{'intdbok'} = 1;
            $ghConfig{'opt'}{'introws'} = " fetch first "; 
        }
    }
    elsif( lc($ghConfig{'opt'}{'intdb'}) eq 'mssql' ){
        if( DEBUG == 1 ){ printf( "MS SQL is only supported on Windows right now\n" ); }
            printf( "Currently attemping MS SQL on: $^O\n" );
    }
    else{ 
        printf( "Unable to identify internal DB type $ghConfig{'opt'}{'intdb'}\n" );
        printf( "Supported internal DB types are SQLite, Oracle, and DB2\n" );
        return( FAILED );
    }

    if( DEBUG == 1 ){ printf( "Init completed\n" ); }

}
#/**************************** End of Init sub *******************************/

#/****************************************************************************/
#/* Read in all of the stored settings and config. Load optionals, etc      **/
#/****************************************************************************/
sub Get_Config{
    # Read command line arguments
    # The Getopt::Long automatically handles both - and --, as well as allowing
    # the very minimum number of unique characters. Both h and host would be
    # equiv and not require me to break them out.
    # These variables will return undef/defined based on use.
    my($verbose, $help, $version, $configure, $check, $server, $database, $batch, $web);
    GetOptions(
        "verbose"               => \$verbose,
        "help|?"                => \$help,
        "version|about|V"       => \$version,
        "configure|reconfigure" => \$configure,
        "check=s"               => \$check,
        "server=s"              => \$server,
        "database|db=s"         => \$database,
        "batch=s"               => \$batch,
        "web"                   => \$web
    );
    if( defined($version) ){
        printf( "$gcVersion\n" );
        exit;
    }
    if( defined($help) ){
        printf( "$gcHelp\n" );
        exit;
    }
    if( defined($verbose) ){ $ghConfig{'arg'}{'verbose'} = 1; }
    if( defined($configure) ){ $ghConfig{'arg'}{'configure'} = 1; }
    if( defined($check) ){
        printf( "Checking $check only\n" );
        $ghConfig{'arg'}{'check'} = $check;
    }
    if( (defined($server)) && (defined($database)) ){
        Fail_Out("The switches --server and --database are exclusive. \nEither one means to check *only* that item." );
    }
    elsif( defined($server) ){
        printf( "Checking $server only\n" );
        $ghConfig{'arg'}{'server'} = $server;
    }
    elsif( defined($database) ){
        printf( "Checking $database only\n" );
        $ghConfig{'arg'}{'database'} = $database;
    }
    if( defined($batch) ){ $ghConfig{'arg'}{'batch'} = $batch; }
    if( defined($web) ) { $ghConfig{'arg'}{'web'} = "web"; }


    # Process constants
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Reading Config\n" ); }
    if( DB == 1 ){ require DBI; }
    if( PARALLEL == 1 ){ require Parallel::ForkManager; }
    if( CRYPTO == 1 ){
        require Crypt::CBC;
        require Crypt::Blowfish;
    }

    # Read in the XML config
    $ghConfig{'opt'} = $gXMLopt->XMLin($gcCfgFile);
    if( DEBUG == 1 ){ 
        printf( "Options read from the config file:\n" );
        print Dumper($ghConfig{'opt'}); 
    }

    # We test the config file version against the program version
    # This ensures that the XML file has the right sort of data, and that
    # we're able to read it properly.
    if( $ghConfig{'opt'}{'heronversion'} == VERSION ){ return( SUCCEEDED ); }
    else{ 
        $ghConfig{'opt'} = $ghConfig{'def'};
        return( FAILED );
    }
}
#/************************** End of Get_Config sub ***************************/


#/****************************************************************************/
#/* Handle the preparations and testing of an internal SQLite DB            **/
#/****************************************************************************/
sub Init_SQLite{
    if( DEBUG == 1 ){ printf( "Running tests on $ghConfig{'opt'}{'intdb'} DB connection\n" ); }

    # Validate we can query from it. Every single db seems to have a
    # different syntax to get one row, so we can't lump this at the end
    # We will silence the error, since we're going to handle it.
    if( $ghConfig{'opt'}{'maxtspaces'} == undef ){ $ghConfig{'opt'}{'maxtspaces'} = $ghConfig{'def'}{'maxtspaces'}; }
    if( -e $ghConfig{'opt'}{'intdbname'} ){
        eval { 
            my $dbh = DBI->connect("dbi:SQLite:dbname=$ghConfig{'opt'}{'intdbname'}","","", {PrintError=>0});
            my $rows = $dbh->do("select hkey, audit, live from host_key limit 1") or die;
            if( $rows ){ 
                if( DEBUG == 1 ){ printf( "The $ghConfig{'opt'}{'intdb'} DB connection test was successful\n" ); }
            }
        }; Create_SQLite("The $ghConfig{'opt'}{'intdb'} DB $ghConfig{'opt'}{'intdbname'} does not exist or is unreachable. \n") if $@;

        eval { 
            if( DEBUG == 1 ){ printf( "Checking the max tablespaces\n" ); }
            my $dbh = DBI->connect("dbi:SQLite:dbname=$ghConfig{'opt'}{'intdbname'}","","", {PrintError=>0});
            my $rows = $dbh->do("select hkey, tbsname$ghConfig{'opt'}{'maxtspaces'} from space_info") or die;
            if( $rows ){ 
                if( DEBUG == 1 ){ printf( "The $ghConfig{'opt'}{'intdb'} DB connection test was successful\n" ); }
            }
        }; Fail_Out("$ghConfig{'opt'}{'intdbname'} has too few tablespace columns in space_info & space_hist."  ) if $@;
    }
    else{
        Create_SQLite("The $ghConfig{'opt'}{'intdb'} DB $ghConfig{'opt'}{'intdbname'} does not exist or is unreachable. ");
    }

    # Now that we should have a good handle, we'll make it global
    $gDBH = DBI->connect("dbi:SQLite:dbname=$ghConfig{'opt'}{'intdbname'}","","") 
        or Fail_Out("Unable to connect: $DBI::errstr\n");

    return( SUCCEEDED );
}
#/************************* End of Init_SQLite sub ***************************/


#/****************************************************************************/
#/* Create an internal SQLite DB if missing                                 **/
#/****************************************************************************/
sub Create_SQLite{
    # Notify that we're going to build the DB, in case this is not desired
    # Quick basic schema overview:
    # host_key: hkey(auto), hostname(unique), audit, live
    # db_key:   dkey(auto), dbname(unique), audit, live
    # user_key: ukey(auto), userid, locked
    # host/db/user/tablespace tables do NOT have any constraints. The goal is 
    # to use the constraints provided by the key tables. At most there is a unique.
    # The dbname can't be unique in db_key due to MS using the same 5 dbs on
    # every instance
    # sess_key: skey(auto), gkey, status, rw
    # gui_key:  gkey(auto), guiuser(unique), locked, hash, salt, modify, add, delete
    # changes:  ckey(auto), skey, gkey, status, mod_rec, add_rec, del_rec, loc, chstring, retval
    # TODO: if I break out a PM, this REALLY belongs there.
    if( DEBUG == 1 ){ printf( "No DB found, prompting to create\n" ); }
    printf( "@_[0] " );
    my $input = Prompt_User("Create/Fix?","y","bool");
    if( $input eq 'n'){
        printf( "Exiting.\n" );
        Fail_Out("Unable to connect to $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    }

    # Re-enabling error output
    $gDBH->{PrintError} = 1;
    $gDBH = DBI->connect("dbi:SQLite:dbname=$ghConfig{'opt'}{'intdbname'}","","") 
        or Fail_Out("Unable to connect: $DBI::errstr\n");

        # Create SQLite DB if missing
    my $sth_hkey = $gDBH->prepare("create table if not exists host_key ('hkey' integer primary key autoincrement not null, 'hostname' varchar unique not null, 'audit' integer not null default 0, 'live' integer not null default 0)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_dkey = $gDBH->prepare("create table if not exists db_key ('dkey' integer primary key autoincrement not null, 'dbname' varchar not null, 'audit' integer not null default 0, 'live' integer not null default 0)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_ukey = $gDBH->prepare("create table if not exists user_key ('ukey' integer primary key autoincrement not null, 'userid' varchar not null, 'locked' integer not null default 0)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_skey = $gDBH->prepare("create table if not exists sys_key ('skey' integer primary key autoincrement not null, 'serial' varchar not null, 'audit' integer not null default 0, 'live' integer not null default 0)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_system = $gDBH->prepare("create table if not exists sys_info ('skey' integer primary key not null, 'hkey' integer, 'lastupdate' datetime, 'cputype' varchar, 'cpunum' integer, 'arch' varchar, 'ram' integer, 'hbanum' integer, 'rack' varchar, 'datacenter' varchar, 'owner' varchar,'comments' varchar)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_host = $gDBH->prepare("create table if not exists host_info ('hkey' integer primary key not null, 'hostname' varchar not null, 'ip' varchar not null default '127.0.0.1', 'virtual' integer not null default 0, 'production' integer not null default 0, 'os' varchar, 'osver' varchar, 'ospatch' varchar, 'san' varchar, 'cluster' varchar, 'owner' varchar, 'lastupdate' datetime, 'ram' integer,  'uptime' varchar, 'page' integer, 'filemon' varchar,'javaver' varchar, 'javavend' varchar, 'javaverfull' varchar, 'mailserver' varchar, 'adminpass' varchar, 'lastbackup' datetime, 'itar' integer not null default 0, 'cronjobs' varchar, 'comments' varchar)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_db = $gDBH->prepare("create table if not exists db_info ('dkey' integer primary key not null, 'hkey' integer not null, 'rdbms' varchar not null, 'production' integer not null default 0, 'instance' varchar not null, 'cluster' varchar, 'connstring' varchar, 'app' varchar, 'dbname' varchar, 'osuser' varchar, 'owner' varchar, 'lastupdate' datetime, 'adminpass' varchar, 'dbver' varchar, 'veredition' varchar, 'verhuman' varchar, 'lastbackup' datetime, 'backupsched' varchar, 'comments' varchar)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_dbhist = $gDBH->prepare("create table if not exists db_info_hist ('dkey' integer primary key not null, 'hkey' integer not null, 'rdbms' varchar not null, 'production' integer not null default 0, 'instance' varchar not null, 'cluster' varchar, 'connstring' varchar, 'app' varchar, 'dbname' varchar, 'osuser' varchar, 'owner' varchar, 'histdate' datetime, 'adminpass' varchar, 'dbver' varchar, 'veredition' varchar, 'verhuman' varchar, 'lastbackup' datetime, 'backupsched' varchar, 'comments' varchar)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_user = $gDBH->prepare("create table if not exists user_info ('ukey' integer primary key not null, 'dkey' integer not null, 'userid' varchar not null, 'username' varchar, 'default_id' integer not null default 0, 'sysadmin' integer not null default 0, 'createdate' datetime, 'lockdate' datetime, 'ntgroup' integer not null default 0, 'ntuser' integer not null default 0)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    
    # Allow the config file to dictate the number of tablespaces recorded
    if( DEBUG == 1 ){ printf( "Set to record $ghConfig{'opt'}{'maxtspaces'} maximum tablespaces per database.\n" ); }
    my $sth_space_query = "create table if not exists space_info ('dkey' integer primary key not null, 'hkey' integer not null, 'dbsize' integer not null default 0, 'pctfree' decimal(3,2) not null default 0.0";
    for( my $loop = 1; $loop <= $ghConfig{'opt'}{'maxtspaces'}; $loop++ ){
        $sth_space_query = $sth_space_query . ", 'tbsname$loop' varchar, 'tbssize$loop' integer, 'tbspct$loop' decimal(3,2)";
    }
    $sth_space_query = $sth_space_query . ")";

    my $sth_space = $gDBH->prepare($sth_space_query)
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_space_hist_query = "create table if not exists space_info_hist ('dkey' integer primary key not null, 'hkey' integer not null, 'dbsize' integer not null default 0, 'pctfree' decimal(3,2) not null default 0.0, 'histdate' datetime";
    for( my $loop = 1; $loop <= $ghConfig{'opt'}{'maxtspaces'}; $loop++ ){
        $sth_space_hist_query = $sth_space_hist_query . ", 'tbsname$loop' varchar, 'tbssize$loop' integer, 'tbspct$loop' decimal(3,2)";
    }

    $sth_space_hist_query = $sth_space_hist_query . ")";

    my $sth_spacehist = $gDBH->prepare($sth_space_hist_query)
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_sesskey = $gDBH->prepare("create table if not exists sess_key ('skey' integer primary key autoincrement not null, 'gkey' integer not null, 'status' integer not null default 0, 'rw' integer not null default 0)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_gkey = $gDBH->prepare("create table if not exists gui_key ('gkey' integer primary key autoincrement not null, 'guiuser' varchar unique not null, 'hash' varchar not null, 'salt' varchar not null,'locked' integer not null default 0, 'mod_rec' integer not null default 0, 'add_rec' integer not null default 0, 'del_rec' integer not null default 0 )")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    my $sth_ckey = $gDBH->prepare("create table if not exists changes ('ckey' integer primary key autoincrement not null, 'skey' integer not null, 'gkey' integer not null, 'status' varchar not null, 'mod_rec' integer not null default 0, 'add_rec' integer not null default 0, 'del_rec' integer not null default 0, 'loc' integer default 1, 'chstring' varchar, 'retval' varchar )")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    
    $sth_hkey->execute();
    $sth_dkey->execute();
    $sth_ukey->execute();
    $sth_host->execute();
    $sth_db->execute();
    $sth_dbhist->execute();
    $sth_user->execute();
    $sth_space->execute();
    $sth_spacehist->execute();
    $sth_skey->execute();
    $sth_system->execute();
    $sth_gkey->execute();
    $sth_ckey->execute();
    $sth_sesskey->execute();

    # Create the default admin user.
    # TODO: Add a switch to override this password. The password, of course, is the SHA-1 hash of 'admin'
    my $sth_gadm = $gDBH->prepare("insert into gui_key (guiuser, locked, hash, salt, mod_rec, add_rec, del_rec) values('admin','0','d033e22ae348aeb5660fc2140aec35850c4da997','d033e22ae348aeb5660fc2140aec35850c4da997',1,1,1)")
        or Fail_Out("Unable to run SQL on $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");

    $sth_gadm->execute();

    my $rows = $gDBH->do("select hkey, audit, live from host_key limit 1")
        or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    if( $rows ){ 
        if( DEBUG == 1 ){ printf( "The $ghConfig{'opt'}{'intdb'} DB connection test was successful\n" ); }
    }

    return( SUCCEEDED );
}
#/************************* End of Init_SQLite sub ***************************/


#/****************************************************************************/
#/* Handle the preparations and testing of an internal Oracle DB            **/
#/****************************************************************************/
sub Init_Oracle{
    my $gDBH = DBI->connect("dbi:Oracle:$ghConfig{'opt'}{'intdbname'}",$ghConfig{'opt'}{'intdbuser'},$ghConfig{'opt'}{'intdbpass'}) 
        or Fail_Out("Unable to connect: $DBI::errstr\n");

    if( DEBUG == 1 ){ printf( "Running tests on $ghConfig{'opt'}{'intdb'} DB connection\n" ); }

    # Check to see if our schema is in place (NOTE: this is psuedo-code, didn't test yet)
    my $sth = $gDBH->prepare("select * from dba_tables where tablename = 'testdata' ")
        or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    $sth->execute();
    # TODO sth->rows() won't have a value until all read. FIX
    if( $sth->rows() == 0 ){
        # Create Oracle DB tables.
        # Quick basic schema overview:
        # host_key: hkey(auto), hostname(unique), audit, live
        # db_key:   dkey(auto), dbname(unique), audit, live
        # user_key: ukey(auto), userid, locked
        # host/db/user/tablespace tables do NOT have any constraints. The goal is 
        # to use the constraints provided by the key tables
        # TODO: Change this to the valid schema
        my $sth_create1 = $gDBH->prepare("create table testdata (testkey number not null, testval varchar2(4000), constraint testdata_pk primary key (testkey) )") 
            or Fail_Out("Unable to create table: $DBI::errstr\n");
        my $sth_create2 = $gDBH->prepare("create sequence testdata_seq start with 1 increment by 1")
            or Fail_Out("Unable to create sequence: $DBI::errstr\n");
        my $sth_create3 = $gDBH->prepare("create trigger bi_testdata before insert on testdata for each row begin select testdata_seq.nextval into :new.testkey from dual; end;")
            or Fail_Out("Unable to create trigger: $DBI::errstr\n");

        $sth_create1->execute();
        $sth_create2->execute();
        $sth_create3->execute();
    }

    # Validate we can query from it. Every single DB seems to have a
    # different syntax to get one row, so we can't lump this at the end
    $sth = $gDBH->prepare("select * from testdata where rownum = 1")
        or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    $sth->execute();
}
#/************************* End of Init_Oracle sub ***************************/


#/****************************************************************************/
#/* Handle the preparations and testing of an internal DB2 DB               **/
#/****************************************************************************/
sub Init_DB2{
    my $gDBH = DBI->connect("dbi:DB2:$ghConfig{'opt'}{'intdbname'}",$ghConfig{'opt'}{'intdbuser'},$ghConfig{'opt'}{'intdbpass'}) 
        or Fail_Out("Unable to connect: $DBI::errstr\n");

    if( DEBUG == 1 ){ printf( "Running tests on $ghConfig{'opt'}{'intdb'} DB connection\n" ); }

    # Check to see if our schema is in place
    # TODO: Replace psuedo code (for oracle no less) with correct code
    # TODO sth->rows() won't have a value until all read. FIX
    my $sth = $gDBH->prepare("select * from dba_tables where tablename = 'testdata' ")
        or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    $sth->execute();
    if( $sth->rows() == 0 ){
        # Create DB2 DB tables.
        # TODO: Change this to the valid schema
        my $sth_create1 = $gDBH->prepare("create table testdata (testkey number not null, testval varchar2(4000), constraint testdata_pk primary key (testkey) )") 
            or Fail_Out("Unable to create table: $DBI::errstr\n");
        my $sth_create2 = $gDBH->prepare("create sequence testdata_seq start with 1 increment by 1")
            or Fail_Out("Unable to create sequence: $DBI::errstr\n");
        my $sth_create3 = $gDBH->prepare("create trigger bi_testdata before insert on testdata for each row begin select testdata_seq.nextval into :new.testkey from dual; end;")
            or Fail_Out("Unable to create trigger: $DBI::errstr\n");

        $sth_create1->execute();
        $sth_create2->execute();
        $sth_create3->execute();
    }

    # Validate we can query from it. Every single DB seems to have a
    # different syntax to get one row, so we can't lump this at the end
    $sth = $gDBH->prepare("select * from testdata where rownum = 1")
        or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    $sth->execute();
}
#/************************** End of Init_DB2 sub *****************************/


#/****************************************************************************/ 
#/* Configure Heron. In particular, add new DBs or Systems                  **/
#/****************************************************************************/
sub Configure{
    my( $input, $system, $database );
    
    if( @_[0] eq "" ){
 
        printf( "Heron CLI configuration menu\n..............................\n" );
        printf( "Exit                       (0)\n" );
        printf( "Show config                (1)\n" );
        printf( "Show status                (2)\n" );
        printf( "Show systems               (3)\n" );
        printf( "Show databases             (4)\n" );
        printf( "Show users                 (5)\n" );
        printf( "Add/Mod/Decom systems      (6)\n" );
        printf( "Add/Mod/Decom databases    (7)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( DEBUG == 1 ){ printf("User chose option $input\n"); }
        if( $input == 0 ){ exit; }
        elsif( $input == 1 ){Configure('config',   0) }        
        elsif( $input == 2 ){Configure('status',   0) }
        elsif( $input == 3 ){Configure('system',   9) }
        elsif( $input == 4 ){Configure('database', 9) }
        elsif( $input == 5 ){Configure('users',    0) }
        elsif( $input == 6 ){Configure('system',   0) }
        elsif( $input == 7 ){Configure('database', 0) }
        else{ Fail_Out("Unsupported option: $input"); }
    }
    elsif( @_[0] eq 'config' ){
        if( @_[1] == 0 ){
            printf( "Showing Configuration\n..............................\n" );
            if( $ghConfig{'opt'}{'usingdef'} ){
                printf( "Unable to read $gcCfgFile \nDefault values shown.\n" );
            }
            print Dumper($ghConfig{'opt'});
            printf( "..............................\n" );
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( DEBUG == 0 ){ printf("User chose to go to config menu\n"); }
            if( $input == 0 ){ Configure(); }
            else{ Configure(); }
        }
    }
    elsif( @_[0] eq 'status' ){
        if( @_[1] == 0 ){
            printf( "Showing Status\n..............................\n" );
            if( $ghConfig{'opt'}{'intdbok'} ){
                printf( "Internal DB : on\n" );
            }
            if( DEBUG == 1 ){ 
                printf( "Debug mode  : on\n" );
            }
            else{
                printf( "Debug mode  : off\n" );
            }
            if( PARALLEL == 1 ){ 
                printf( "Parallelism : on\n" );
            }
            else{
                printf( "Parallelism : off\n" );
            }
            if( CRYPTO == 1 ){
                printf( "Cryptography: on\n" );
            }
            else{
                printf( "Cryptography: off\n" );
            }
            printf( "..............................\n" );
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            else{ Configure(); }
        }
    }
    elsif( @_[0] eq 'system' ){
        if( @_[1] == 0 ){
            printf( "Add/Mod/Decom system\n..............................\n" );
            printf( "Back                       (0)\n" );
            printf( "Add new system             (1)\n" );
            printf( "Modify system              (2)\n" );
            printf( "Decommission system        (3)\n" );
            #printf( "Show systems               (9)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            else{ Configure('system', $input); }
        }
        elsif( @_[1] == 1 ){
            printf( "Add new system\n..............................\n" );
            Add_Record('cli_sys');
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            Configure('system', $input);
        }
        elsif( @_[1] == 2 ){
            printf( "Modify System\n..............................\n" );
            Modify_Record('cli_sys');
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            Configure('system', $input);
        }
        elsif( @_[1] == 3 ){
            printf( "Decommission System\n..............................\n" );
            Modify_Record('cli_sys_decom');
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            Configure('system', $input);
        }
        elsif( @_[1] == 9 ){
            printf( "Showing all systems\n..............................\n" );
            Show_Systems('basic',10);
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            else{ Configure(); }
        }
        else{
            printf("Unsupported option\n");
            Configure();
        }
    }
    elsif( @_[0] eq 'users' ){
        printf( "Not implemented yet\n" );
        Configure();
    }
    elsif( @_[0] eq 'database' ){
        if( @_[1] == 0 ){
            printf( "Add/Mod/Decom database\n..............................\n" );
            # TODO Add sql to display systems         
            printf( "Back                       (0)\n" );
            printf( "Add new database           (1)\n" );
            printf( "Modify database            (2)\n" );
            printf( "Decommision database       (3)\n" );
            #printf( "Show databases             (9)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            elsif( $input == 1 ){ Configure('database', $input); }
            elsif( $input == 2 ){ Configure('database', $input); }
            elsif( $input == 3 ){ Configure('database', $input); }
            elsif( $input == 9 ){ Configure('database', $input); }
            else{
                printf("Unsupported option\n");
                Configure();
            }
            
        }
        elsif( @_[1] == 1 ){
            printf( "Add new database\n..............................\n" );
            Add_Record('cli_db');
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            else{
                printf("Unsupported option\n");
                Configure();
            }
        }
        elsif( @_[1] == 2 ){
            printf( "Modify database\n..............................\n" );
            Modify_Record('cli_db');
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            else{
                printf("Unsupported option\n");
                Configure();
            }
        }
        elsif( @_[1] == 3 ){
            printf( "Decommision database\n..............................\n" );
            Modify_Record('cli_db_decom');
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            else{
                printf("Unsupported option\n");
                Configure();
            }
        }
        elsif( @_[1] == 9 ){
            printf( "Showing all databases\n..............................\n" );
            Show_Databases('basic',10);
            printf( "Back                       (0)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure(); }
            else{
                printf("Unsupported option\n");
                Configure();
            }
        }
        else{
            printf("Unsupported option\n");
            Configure();
        }
    }
}
#/************************** End of Configure sub ****************************/


#/****************************************************************************/ 
#/* Process the transactions queued up in the changes table.                **/
#/* Only provides basic error checking, not like CLI                        **/
#/****************************************************************************/
sub Run_Web{
    my( @change, $chstatus, $loc, $chstr, $result, $ckey, $sql, $loop, @row, $rec, $sql, $sth, $rowcount );

    for( $loop = 0; $loop < $ghConfig{'opt'}{'maxbtcrec'}; $loop++ ){
        # The maxbtcrec specifies how many changes to process per run
        @change = Next_Change();
        if( $#change > 0 ){
            $ckey = $change[0];
            $chstatus = $change[1];
            $loc = $change[2];
            $chstr = $change[3];
        }
        else{
            if( DEBUG == 1 ){ printf( "No changes left to process: @change\n" ); }
            return(SUCCEEDED);
        }
        
         # TODO: Full on changes will come via a proper XML (like batch). Queries won't.
         # TODO: Changes are two categories - LOCAL (1) and REMOTE (0)
         # Remote queries are going to be handled VERY carefully, local not so much.
        $sql = grep( /select/, $chstr );
        if( DEBUG == 1 ){ printf( "Found $sql in $chstr\n" ); }
        if( $sql > 0 ){
            # This change is actually a select statement.
            # First we parse it for 'issues' then if it's clean
            # we will read it, then execute and store the result in table format (Would XML be better?)
            # The <table> tags are missing - to be added on the display side
            $sql = Scrub_SQL($chstr, 1);
            if( $loc == 1 ){
                if( DEBUG == 1 ){ printf( "Running LOCAL query: $sql\n" ); }
                if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
                $sth = $gDBH->prepare($sql)
                    or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                $sth->execute();
                $result = "";
                while( @row = $sth->fetchrow_array() ) {
                    $result = $result . "<tr>\n";
                    foreach $rec (@row){
                        $result = $result . "<td>$rec</td>\n";
                    }
                    $result = $result . "</tr>\n";
                }

                if( $sth->rows() < 1 ){
                    if( DEBUG == 1 ){ printf( "No rows returned\n" ); }
                    $result = "<tr><td>No Results Returned</td</tr>\n";
                }
                $rowcount = $gDBH->do( "$ghConfig{'sql'}{'intChangeComplete'}, retval=\'$result\' where ckey = \'$ckey\'" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                if( DEBUG == 1 ){ printf( "Marked change \"$ckey\" complete, retval: $result\n" ); }
            }
            else{
                if( DEBUG == 1 ){ printf( "Running REMOTE query: $sql\nNot Supported Yet" ); }
            }
        }
        else{
            if( DEBUG == 1 ){ printf( "Running batch: $chstr\n" ); }
            $ghConfig{'arg'}{'batch'} = $chstr;
            $result = Run_Batch();
        }
    }
    exit;
}
#/************************** End of Run_Web sub ******************************/


#/****************************************************************************/ 
#/* Process a file to receive instructions in batch.                        **/
#/* Only provides basic error checking, not like CLI                        **/
#/****************************************************************************/
sub Run_Batch{
    my( %batch, @servers, @dbs, @rows, $sql, $sth );
    my $xml = XML::Simple->new(RootName=>'steps');
    # Read in the XML instructions
    $batch{'steps'} = $gXMLopt->XMLin($ghConfig{'arg'}{'batch'});
    if( DEBUG == 1 ){ 
        printf( "Options read from the batch file:\n" );
        print Dumper($batch{'steps'}); 
    }
    # We test the batch file version against the program version
    # This ensures that the XML file has the right sort of data, and that
    # we're able to read it properly.
    if( $batch{'steps'}{'heronversion'} != VERSION ){
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Invalid file version\n" ); }
        return( FAILED );
    }

    if( defined($batch{'steps'}{'addserver'}) ){
        # Add a new server
        my( $hostname, $ip, $virtual, $os, $osver, $san, $cluster, $owner, $audit, $live );
        
        # Sanity check values before inserting.
        # Any optional field will come back FAILURE
        $hostname  = Scrub_SQL($batch{'steps'}{'addserver'}{'hostname'}, 1);
        $ip        = Scrub_SQL($batch{'steps'}{'addserver'}{'ip'}, 1);
        $virtual   = Scrub_SQL($batch{'steps'}{'addserver'}{'virtual'}, 1);
        $os        = Scrub_SQL($batch{'steps'}{'addserver'}{'os'}, 1);
        $osver     = Scrub_SQL($batch{'steps'}{'addserver'}{'osver'}, 1);
        $san       = Scrub_SQL($batch{'steps'}{'addserver'}{'san'}, 1);
        $cluster   = Scrub_SQL($batch{'steps'}{'addserver'}{'cluster'}, 1);
        $owner     = Scrub_SQL($batch{'steps'}{'addserver'}{'owner'}, 1);
        $audit     = Scrub_SQL($batch{'steps'}{'addserver'}{'audit'}, 1);
        $live      = Scrub_SQL($batch{'steps'}{'addserver'}{'live'}, 1);

        # Set the y/n to bool 0/1
        $audit   eq 'y' ? ($audit = 1)   : ($audit = 0);
        $virtual eq 'y' ? ($virtual = 1) : ($virtual = 0);
        $live    eq 'y' ? ($live = 1)    : ($live = 0);
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){
            printf( "Add new system\n" );
            printf( "Hostname: $hostname\n" );
            printf( "IP      : $ip\n" );
            printf( "Virtual : $virtual\n" );
            printf( "OS      : $os\n" );
            printf( "OS ver  : $osver\n" );
            printf( "SAN     : $san\n" );
            printf( "Cluster : $cluster\n" );
            printf( "Owner   : $owner\n" );
            printf( "Audited : $audit\n" );
            printf( "Live    : $live\n" );
        }

        # Prevent duplicate hostnames
        $sql = "select hkey, hostname, live from host_key where hostname = '$hostname' ";
        if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
        $sth = $gDBH->prepare($sql)
            or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        $sth->execute();
        while( @rows = $sth->fetchrow_array() ){
            push( @servers, $rows[0] );
            push( @servers, "$rows[1]\n" );
        }
        if( $sth->rows() > 0 ){ if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Duplicate server(s): @servers found, cancelling\n" ); } }
        else{ Create_System( $hostname, $ip, $virtual, $os, $osver, $san, $cluster, $owner, $audit, $live ); }

    }
    if( defined($batch{'steps'}{'adddatabase'}) ){
        # Add a new database
        my( $hostname, $hkey, $dbname, $rdbms, $instance, $cluster, $connstring, $app, $prod, $owner, $comments, $backupsched, $audit, $live );
        
        # Sanity check values before inserting.
        # Any optional field will come back FAILURE
        $hostname    = Scrub_SQL($batch{'steps'}{'adddatabase'}{'hostname'}, 1);
        $dbname      = Scrub_SQL($batch{'steps'}{'adddatabase'}{'dbname'}, 1);
        $rdbms       = lc(Scrub_SQL($batch{'steps'}{'adddatabase'}{'rdbms'}, 1));
        $instance    = Scrub_SQL($batch{'steps'}{'adddatabase'}{'instance'}, 1);
        $cluster     = Scrub_SQL($batch{'steps'}{'adddatabase'}{'cluster'}, 1);
        $connstring  = Scrub_SQL($batch{'steps'}{'adddatabase'}{'connstring'}, 1);
        $app         = Scrub_SQL($batch{'steps'}{'adddatabase'}{'app'}, 1);
        $prod        = Scrub_SQL($batch{'steps'}{'adddatabase'}{'prod'}, 1);
        $owner       = Scrub_SQL($batch{'steps'}{'adddatabase'}{'owner'}, 1);
        $comments    = Scrub_SQL($batch{'steps'}{'adddatabase'}{'comments'}, 1);
        $backupsched = Scrub_SQL($batch{'steps'}{'adddatabase'}{'backupsched'}, 1);
        $audit       = Scrub_SQL($batch{'steps'}{'adddatabase'}{'audit'}, 1);
        $live        = Scrub_SQL($batch{'steps'}{'adddatabase'}{'live'}, 1);

        # Set the y/n to bool 0/1
        $audit   eq 'y' ? ($audit = 1)   : ($audit = 0);
        $prod    eq 'y' ? ($prod = 1)    : ($prod = 0);
        $live    eq 'y' ? ($live = 1)    : ($live = 0);

        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){
            printf( "Add new database\n" );
            printf( "Hostname   : $hostname\n" );
            printf( "DB Name    : $dbname\n" );
            printf( "RDBMS      : $rdbms\n" );
            printf( "Instance   : $instance\n" );
            printf( "Cluster    : $cluster\n" );
            printf( "Connection : $connstring\n" );
            printf( "Application: $app\n" );
            printf( "Production : $prod\n" );
            printf( "Owner      : $owner\n" );
            printf( "Comments   : $comments\n" );
            printf( "Backup Schd: $backupsched\n" );
            printf( "Audited    : $audit\n" );
            printf( "Live       : $live\n" );
        }

        # First we map hostname to host key
        $sql = "select hkey, hostname from host_key where hostname = '$hostname' ";
        if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
        $sth = $gDBH->prepare($sql)
            or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        $sth->execute();
        while( @rows = $sth->fetchrow_array() ){
            $hkey     = $rows[0];
            $hostname = $rows[1];                
        }
        if( $sth->rows() == 1 ){ if( DEBUG == 1 ){ printf( "Will be using $hostname\n" ); } }
        else{ 
            if( $sth->rows() > 1 ){ if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Too many hosts found, cancelling\n" ); } } 
            elsif( $sth->rows() < 1 ){ if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "No hosts found, cancelling\n" ); } } 
        }

        # Now we prevent duplicate DBnames
        $sql = "select dkey, dbname, live from db_key where dbname = '$dbname' ";
        if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
        $sth = $gDBH->prepare($sql)
            or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        $sth->execute();
        while( @rows = $sth->fetchrow_array() ){
            push( @dbs, $rows[0] );
            push( @dbs, "$rows[1]\n" );
        }
        if( $sth->rows() > 0 ){ if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Duplicate database(s): @dbs found, cancelling\n" ); } }
        else{ Create_Database( $hkey, $dbname, $rdbms, $instance, $cluster, $connstring, $app, $prod, $owner, $comments, $backupsched, $audit, $live ); }
    }
    if( defined($batch{'steps'}{'decomserver'}) ){
        printf( "Decom not implemented yet\n" );
        # TODO: Implement decom
    }
    if( defined($batch{'steps'}{'decomdatabase'}) ){
        printf( "Decom not implemented yet\n" );
        # TODO: Implement decom
    }
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Completed processing batch\n" ); }

    return( SUCCEEDED );
}
#/************************* End of Run_Batch sub *****************************/


#/****************************************************************************/
#/* Get next change from DB. Checks for validity, returns one at a time.    **/
#/****************************************************************************/
sub Next_Change{
    my( $sth, $sql, @row, $filter, $exclude, $rowlimit, $rowcount );
    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Getting Next Change\n" ); };
    
    # Pop the first change record off the table
    # create example change:
    # insert into changes(skey,gkey,status,mod_rec,add_rec,del_rec,chstring) values(0,0,'new',0,0,0,'select dbname,app,connstring from db_info');
    $rowlimit = 1;
    $sql = "$ghConfig{'sql'}{'intChangeNext'} $ghConfig{'opt'}{'introws'} $rowlimit";
    if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
    $sth = $gDBH->prepare($sql)
        or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
    $sth->execute();
    while( @row = $sth->fetchrow_array() ) {
        $rowcount = $gDBH->do( "$ghConfig{'sql'}{'intChangeActive'} where ckey = \'$row[0]\'" )
            or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        if( DEBUG == 1 ){ printf( "Marked change \"@row\" in progress\n" ); }
        if( DEBUG == 1 ){ printf( "Returned Next Change: @row\n" ); }
        return( @row );
    }
    if( $sth->rows() < 1 ){
        if( DEBUG == 1 ){ printf( "No rows returned\n" ); }
        return();
    }
}
#/************************ End of Next_Change sub ****************************/

#/****************************************************************************/
#/* Show systems. Expects a detail level and a rowlimit                     **/
#/****************************************************************************/
sub Show_Systems{
    my( $sth, $sql, @row, $filter, $exclude, $rowlimit );
    
    if( defined @_[1] ){ $rowlimit = Scrub_SQL( @_[1] ); }
    if( defined @_[2] ){ $filter   = Scrub_SQL( @_[2] ); }
    if( defined @_[3] ){ $exclude  = Scrub_SQL( @_[3] ); }

    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Show Systems\n" ); };
    if( @_[0] eq 'basic' ){
        if( defined(@_[1]) ){
            $sql = "select $ghConfig{'sql'}{'intShortHostInf'} where hostname like '%$filter%' $ghConfig{'opt'}{'introws'} $rowlimit";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        else{
            $sql = "select $ghConfig{'sql'}{'intShortHostInf'} where hostname like '%$filter%' ";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        
        $sth->execute();
        while( @row = $sth->fetchrow_array() ) {
            printf( "@row\n" );
        }
        if( $sth->rows() < 1 ){
            printf( "No rows returned\n" );
        }
    }
    elsif( @_[0] eq 'menu' ){
        # Same as basic, but we display the hkey on the right like a selection option
        if( defined(@_[1]) ){
            $sql = "select hostname, hkey from host_key where hostname like '%$filter%' $ghConfig{'opt'}{'introws'} @_[1]";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        else{
            $sql = "select $ghConfig{'sql'}{'intShortHostInf'}";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        
        $sth->execute();
        while( @row = $sth->fetchrow_array() ) {
            printf( "%-25s  (%s)\n", $row[0], $row[1] );
        }
        if( $sth->rows() < 1 ){
            printf( "No rows returned\n" );
        }
    }
    else{
        # Default to basic, but show 10 rows only
        # TODO: Add basic query, 10 rows only
        $sth = $gDBH->prepare("select $ghConfig{'sql'}{'intShortHostInf'} where hostname like '%$filter%' $ghConfig{'opt'}{'introws'} 10")
            or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        $sth->execute();
        while( @row = $sth->fetchrow_array() ) {
            printf( "@row\n" );
        }
        if( $sth->rows() < 1 ){
            printf( "No rows returned\n" );
        }
    }
}
#/************************ End of Show_Systems sub ***************************/


#/****************************************************************************/
#/* Show databases. Expects a detail level and a rowlimit                   **/
#/****************************************************************************/
sub Show_Databases{
    my( $sth, $sql, @row, $filter, $exclude, $rowlimit );

    if( defined @_[1] ){ $rowlimit = Scrub_SQL( @_[1] ); }
    if( defined @_[2] ){ $filter   = Scrub_SQL( @_[2] ); }
    if( defined @_[3] ){ $exclude  = Scrub_SQL( @_[3] ); }

    if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Show Databases\n" ); };
    if( @_[0] eq 'basic' ){
        if( defined(@_[1]) ){
            $sql = "select $ghConfig{'sql'}{'intShortDBInf'} where dbname like '%$filter%' $ghConfig{'opt'}{'introws'} $rowlimit";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        else{
            $sql = "select $ghConfig{'sql'}{'intShortDBInf'} where dbname like '%$filter%' ";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        
        $sth->execute();
        while( @row = $sth->fetchrow_array() ) {
            printf( "@row\n" );
        }
        if( $sth->rows() < 1 ){
            printf( "No rows returned\n" );
        }
    }
    elsif( @_[0] eq 'menu' ){
        # Same as basic, but we display the dbkey on the right like a selection option
        if( defined(@_[1]) ){
            $sql = "select dbname, dkey from db_key where dbname like '%$filter%' $ghConfig{'opt'}{'introws'} $rowlimit";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        else{
            $sql = "select dbname, dkey from db_key where dbname like '%$filter%' $ghConfig{'opt'}{'introws'} 10 ";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        }
        
        $sth->execute();
        while( @row = $sth->fetchrow_array() ) {
            printf( "%-25s  (%s)\n", $row[0], $row[1] );
        }
        if( $sth->rows() < 1 ){
            printf( "No rows returned\n" );
        }
    }
    else{
        # Default to basic, but show 10 rows only
        # TODO: Add basic query, 10 rows only
        $sth = $gDBH->prepare("select $ghConfig{'sql'}{'intShortDBInf'} where dbname like '%$filter%' $ghConfig{'opt'}{'introws'} 10")
            or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
        $sth->execute();
        while( @row = $sth->fetchrow_array() ) {
            printf( "@row\n" );
        }
        if( $sth->rows() < 1 ){
            printf( "No rows returned\n" );
        }
    }
}
#/*********************** End of Show_Databases sub **************************/


#/****************************************************************************/
#/* Add new record. Expects a mode: cli_ or batch_ and a record type.       **/
#/****************************************************************************/
sub Add_Record{
    my( $sth, $sql, @rows, $hostname, $ip, $virtual, $os, $osver, $san, $cluster, $owner, $live, $audit, $input, @servers, $dbname, $rdbms, $instance, $connstring, $app, $prod, $comments, $backsched, $hkey );
 
    if( @_[0] eq 'cli_sys' ){
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Add System CLI mode\n" ); };
        printf( "Add system\n..............................\n" );       

        # Get and check hostname
        $input = Prompt_User( "Hostname", "localhost", "hostname" );
        if( DEBUG == 1 ){ printf( "Returned $input for hostname\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $hostname = $input;
        }

        # Get and check IP Address
        # TODO: This is IPv4 only - needs to have IPv6 support too
        $input = Prompt_User( "IP Address", "127.0.0.1", "ip" );
        if( DEBUG == 1 ){ printf( "Returned $input for IP\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $ip = $input;
        }

        # Get virtualization stats. Yes/no type answers only
        $input = Prompt_User( "Virtualized", "n", "bool" );
        if( DEBUG == 1 ){ printf( "Returned $input for virtualization\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $virtual = $input;
        }

        # Get live info stats. Yes/no type answers only
        $input = Prompt_User( "Live", "y", "bool" );
        if( DEBUG == 1 ){ printf( "Returned $input for live\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $live = $input;
        }

        # Get audit info stats. Yes/no type answers only
        $input = Prompt_User( "Audited", "n", "bool" );
        if( DEBUG == 1 ){ printf( "Returned $input for audit\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $audit = $input;
        }

        # Get and check OS. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "OS (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for OS\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $os = $input;
        }

        # Get and check OS version. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "OS Version (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for OS Version\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $osver = $input;
        }

        # Get and check SAN. Pretty much free text, so a user can provide 
        # any SAN details useful to them (like SAN name, address, etc)
        $input = Prompt_User( "SAN (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for SAN\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $san = $input;
        }

        # Get and check Cluster. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "Cluster (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for Cluster\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $cluster = $input;
        }

        # Get and check Owner. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "Owner (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for Owner\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('system', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_sys');
        }
        else{
            $owner = $input;
        }

        # Done, confirm and add host entry
        printf( "\nPlease review the details below\n..............................\n" );
        printf( "Hostname: $hostname\n" );
        printf( "IP      : $ip\n" );
        printf( "Virtual : $virtual\n" );
        printf( "OS      : $os\n" );
        printf( "OS ver  : $osver\n" );
        printf( "SAN     : $san\n" );
        printf( "Cluster : $cluster\n" );
        printf( "Owner   : $owner\n" );
        printf( "Audited : $audit\n" );
        printf( "Live    : $live\n" );
        printf( "..............................\n" );
        printf( "Back (Cancel)              (0)\n" );
        printf( "Confirm                    (1)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('system', 0); }
        elsif( $input == 1 ){
            # First we're going to query and see if this host already exists
            # If something similar exists, we ask if it's the same host
            # Same host (maybe new domain name or something) we mod instead
            # TODO: Maybe use Show_Systems('menu',10,$hostname); instead?

            # Set the y/n to bool 0/1
            $audit   eq 'y' ? ($audit = 1)   : ($audit = 0);
            $virtual eq 'y' ? ($virtual = 1) : ($virtual = 0);
            $live    eq 'y' ? ($live = 1)    : ($live = 0);

            $sql = "select hkey, hostname, live from host_key where hostname like '%$hostname%' ";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                push( @servers, $rows[0] );
                push( @servers, "$rows[1]\n" );
            }
            if( $sth->rows() > 0 ){
                printf( "These servers are similar: @servers\n" );
                $input = Prompt_User( "Are you modifying an existing server", "n", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for modifying\n" ); }
                if( $input =~ /^[0]+$/ ){
                    Configure('system', 0);
                }
                elsif( $input eq 'n' ){
                    printf( "Adding system\n" );
                    Create_System( $hostname, $ip, $virtual, $os, $osver, $san, $cluster, $owner, $audit, $live );
                }
                else{
                    printf( "Not adding...\n" );
                }
            }
            else{
                printf( "Adding System\n" );                
                Create_System( $hostname, $ip, $virtual, $os, $osver, $san, $cluster, $owner, $audit, $live );
            }
            return( SUCCEEDED );
        }
        else{
            printf("Unsupported option\n");
            Configure('system', 0);
        }
    }
    elsif( @_[0] eq 'cli_db' ){
        # Database is a bit tricky - it should have a host key and a unique db key
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Add Database CLI mode\n" ); };
        printf( "Add database\n..............................\n" );

        # Get and check hostname
        printf( "Back                       (0)\n" );
        printf( "Select host from list      (1)\n" );
        printf( "Search for host by name    (2)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('database', 0); }
        if( $input == 1 ){ $hostname = ""; }
        elsif( $input == 2 ){
            $input = Prompt_User( "Hostname", "localhost", "hostname" );
            if( DEBUG == 1 ){ printf( "Returned $input for hostname\n" ); }
            if( $input =~ /^[0]+$/ ){
                Configure('database', 0);
            }
            elsif( $input == FAILED ){
                Add_Record('cli_db');
            }
            else{
                $hostname = $input;
            }
        }

        # All options that pass through should get here:
        printf( "Back                       (0)\n" );
        Show_Systems('menu',10,$hostname);
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('database', 0); }
        else{
            $sql = "select hostname from host_key where hkey = $input";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];                
            }
            if( $sth->rows() > 0 ){ printf( "Will be using $hostname\n" ); }
            else{ 
                printf( "Error attempting to find system\n" );
                Configure('database',0);
            }
            $hkey = $input;
        }

        # Get and check the database name. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "DBName", "mydb", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for DB name\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $dbname = $input;
        }

        # Get and check the RDBMS. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "RDBMS", "oracle", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for instance\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $rdbms = lc($input);
        }

        # Get and check the instance. Pretty much free text, but alpha-numeric
        # If the RDBMS is MSSQL, we default to default. For oracle, to dbname
        if( $rdbms eq 'mssql' ){
            $input = Prompt_User( "Instance", "Default", "" );
        }
        else{
            $input = Prompt_User( "Instance", $dbname, "" );
        }
        if( DEBUG == 1 ){ printf( "Returned $input for instance\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $instance = $input;
        }

        # Get and check the cluster. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "Cluster (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for cluster\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $cluster = $input;
        }

        # Get and check the Connection string. Pretty much free text. Allow / and :
        $input = Prompt_User( "Connection String", "//$hostname:1521/$instance", "uri" );
        if( DEBUG == 1 ){ printf( "Returned $input for instance\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $connstring = lc($input);
        }        

        # Get and check the app. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "Application (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for app\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $app = $input;
        }
        
        # Get prod status. Yes/no type answers only
        $input = Prompt_User( "Production", "y", "bool" );
        if( DEBUG == 1 ){ printf( "Returned $input for prod\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $prod = $input;
        }

        # Get and check the owner. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "Owner (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for owner\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $owner = $input;
        }

        # Get and check the comments. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "Comments (optional)", "", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for comments\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $comments = $input;
        }

        # Get and check the backup schedule. Pretty much free text, but alpha-numeric
        $input = Prompt_User( "Backup Schedule (optional)", "MWF", "" );
        if( DEBUG == 1 ){ printf( "Returned $input for comments\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $backsched = $input;
        }

        # Get audit info stats. Yes/no type answers only
        $input = Prompt_User( "Audited", "n", "bool" );
        if( DEBUG == 1 ){ printf( "Returned $input for audit\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $audit = $input;
        }

        # Get live info stats. Yes/no type answers only
        $input = Prompt_User( "Live", "y", "bool" );
        if( DEBUG == 1 ){ printf( "Returned $input for live\n" ); }
        if( $input =~ /^[0]+$/ ){
            Configure('database', 0);
        }
        elsif( $input == FAILED ){
            Add_Record('cli_db');
        }
        else{
            $live = $input;
        }

 
        # Done, confirm and add db entry
        printf( "\nPlease review the details below\n..............................\n" );
        printf( "Hostname   : $hostname\n" );
        printf( "DB Name    : $dbname\n" );
        printf( "RDBMS      : $rdbms\n" );
        printf( "Instance   : $instance\n" );
        printf( "Cluster    : $cluster\n" );
        printf( "Connection : $connstring\n" );
        printf( "Application: $app\n" );
        printf( "Production : $prod\n" );
        printf( "Owner      : $owner\n" );
        printf( "Comments   : $comments\n" );
        printf( "Backup Schd: $backsched\n" );
        printf( "Audited    : $audit\n" );
        printf( "Live       : $live\n" );
        printf( "..............................\n" );
        printf( "Back (Cancel)              (0)\n" );
        printf( "Confirm                    (1)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('database', 0); }
        elsif( $input == 1 ){
            # First we're going to query and see if this host already exists
            # If something similar exists, we ask if it's the same db
            # Now, with MS SQL, there are TONS of duplicates, since MS lists
            # the internal system tables. We want to weed those out.

            # Set the y/n to bool 0/1
            $audit   eq 'y' ? ($audit = 1)   : ($audit = 0);
            $virtual eq 'y' ? ($virtual = 1) : ($virtual = 0);
            $live    eq 'y' ? ($live = 1)    : ($live = 0);
            $prod    eq 'y' ? ($prod = 1)    : ($prod = 0);

            if( $rdbms eq 'MSSQL' ){
                $sql = "select dkey, dbname, live from db_key where dbname like '%$dbname%' and dbname not in ('master', 'model', 'msdb', 'Northwind', 'pubs', 'tempdb')  ";
            }
            else{
                $sql = "select dkey, dbname, live from db_key where dbname like '%$dbname%'  ";
            }

            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                push( @servers, $rows[0] );
                push( @servers, "$rows[1]\n" );
            }
            if( $sth->rows() > 0 ){
                printf( "These databases are similar: @servers\n" );
                $input = Prompt_User( "Are you modifying an existing DB", "n", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for modifying\n" ); }
                if( $input =~ /^[0]+$/ ){
                    Configure('database', 0);
                }
                elsif( $input eq 'n' ){
                    printf( "Adding database\n" );
                    Create_Database( $hkey, $dbname, $rdbms, $instance, $cluster, $connstring, $app, $prod, $owner, $comments, $backsched, $audit, $live );
                }
                else{
                    printf( "Not adding...\n" );
                }
            }
            else{
                printf( "Adding database\n" );                
                Create_Database( $hkey, $dbname, $rdbms, $instance, $cluster, $connstring, $app, $prod, $owner, $comments, $backsched, $audit, $live );
            }
            return( SUCCEEDED );
        }
        else{
            printf("Unsupported option\n");
            Configure('database', 0);
        }
    }
    else{
        # TODO: Add the batch and web-driven modes
    }
}
#/************************* End of Add_Record sub ****************************/


#/****************************************************************************/
#/* Modify record. Expects a mode: cli_ or batch_ and a record type.        **/
#/****************************************************************************/
sub Modify_Record{
    my( $sth, $sql, @rows, $hostname, $ip, $virtual, $os, $osver, $san, $cluster, $owner, $live, $audit, $input, @servers, $dbname, $rdbms, $instance, $conn, $app, $prod, $comments, $backschd, $hkey, $dkey, $rowcount );
    
    if( @_[0] eq 'cli_sys_decom' ){
        # Decom is a simplified modify - just sets the live and audit to 0/n.
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Decom System CLI mode\n" ); };
        printf( "Decom system\n..............................\n" );
        # Get and check hostname
        printf( "Back                       (0)\n" );
        printf( "Select host from list      (1)\n" );
        printf( "Search for host by name    (2)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('system', 0); }
        if( $input == 1 ){ $hostname = ""; }
        elsif( $input == 2 ){
            $input = Prompt_User( "Hostname", "localhost", "hostname" );
            if( DEBUG == 1 ){ printf( "Returned $input for hostname\n" ); }
            if( $input =~ /^[0]+$/ ){
                Configure('system', 0);
            }
            elsif( $input == FAILED ){
                Modify_Record('cli_sys_decom');
            }
            else{
                $hostname = $input;
            }
        }

        # All options that pass through should get here:
        printf( "Back                       (0)\n" );
        Show_Systems('menu',10,$hostname);
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('system', 0); }
        else{
            $hkey = $input;
            $sql = "select hostname from host_key where hkey = $hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];                
            }
            if( $sth->rows() > 0 ){ printf( "Will be using $hostname\n" ); }
            else{ 
                printf( "Error attempting to find system\n" );
                Configure('system',0);
            }
            $hkey = $input;

            $sql = "select k.hostname, h.ip, h.virtual, h.os, h.osver, h.san, h.cluster, h.owner, k.audit, k.live from host_key k, host_info h where h.hkey = $hkey and k.hkey = h.hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];
                $ip       = $rows[1];
                $virtual  = $rows[2];
                $os       = $rows[3];
                $osver    = $rows[4];
                $san      = $rows[5];
                $cluster  = $rows[6];
                $owner    = $rows[7];
                $audit    = $rows[8];
                $live     = $rows[9];
            }
            
            if( $sth->rows() > 0 ){ 
                # Display current values
                printf( "\nDecom system?\n..............................\n");
                printf( "Hostname: %-15s  \n", $hostname );
                printf( "IP      : %-15s  \n", $ip );
                printf( "Virtual : %-15s  \n", $virtual );
                printf( "OS      : %-15s  \n", $os );
                printf( "OS ver  : %-15s  \n", $osver );
                printf( "SAN     : %-15s  \n", $san );
                printf( "Cluster : %-15s  \n", $cluster );
                printf( "Owner   : %-15s  \n", $owner );
                printf( "Audited : %-15s  \n", $audit );
                printf( "Live    : %-15s  \n", $live );
            }
            else{ 
                printf( "Error attempting to find system\n" );
                Configure('system',0);
            }
            printf( "..............................\n" );
            printf( "Back (Cancel)              (0)\n" );
            printf( "Confirm                    (1)\n" );
            printf( "..............................\n" );
            
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure('system', 0); }
            elsif( $input == 1 ){
                $rowcount = $gDBH->do( "update host_key set live = '0', audit = '0' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "System is no longer live.\n" );
            }
        }
    }
    if( @_[0] eq 'cli_db_decom' ){
        # Decom is a simplified modify - just sets the live and audit to 0/n.
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Decom Database CLI mode\n" ); };
        printf( "Decom database\n..............................\n" );
        # Get and check db name
        printf( "Back                       (0)\n" );
        printf( "Select db from list        (1)\n" );
        printf( "Search for db by name      (2)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('database', 0); }
        if( $input == 1 ){ $dbname = ""; }
        elsif( $input == 2 ){
            $input = Prompt_User( "Database Name", "mydb", "" );
            if( DEBUG == 1 ){ printf( "Returned $input for dbname\n" ); }
            if( $input =~ /^[0]+$/ ){
                Configure('database', 0);
            }
            elsif( $input == FAILED ){
                Modify_Record('cli_db_decom');
            }
            else{
                $dbname = $input;
            }
        }

        # All options that pass through should get here:
        printf( "Back                       (0)\n" );
        Show_Databases('menu',10,$dbname);
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('databases', 0); }
        else{
            $dkey = $input;
            $sql = "select dbname from db_key where dkey = $dkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $dbname = $rows[0];                
            }
            if( $sth->rows() > 0 ){ printf( "Will be using $dbname\n" ); }
            else{ 
                printf( "Error attempting to find database\n" );
                Configure('database',0);
            }

            $sql = "select h.hostname, d.dbname, d.rdbms, d.instance, d.cluster, d.connstring, d.app, d.production, d.owner, d.comments, d.backupsched, k.audit, k.live from host_key h, db_key k, db_info d where k.dkey = $dkey and k.dkey = d.dkey and h.hkey = d.hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];
                $dbname   = $rows[1];
                $rdbms    = $rows[2];
                $instance = $rows[3];
                $cluster  = $rows[4];
                $conn     = $rows[5];
                $app      = $rows[6];
                $prod     = $rows[7];
                $owner    = $rows[8];
                $comments = $rows[9];
                $backschd = $rows[10];
                $audit    = $rows[11];
                $live     = $rows[12];
            }

            if( $sth->rows() > 0 ){ 
                # Display current values
                printf( "\nDecom database?\n..............................\n");
                printf( "Hostname   : %-15s  \n", $hostname );
                printf( "DB Name    : %-15s  \n", $dbname );
                printf( "RDBMS      : %-15s  \n", $rdbms );
                printf( "Instance   : %-15s  \n", $instance );
                printf( "Cluster    : %-15s  \n", $cluster );
                printf( "Connstr    : %-15s  \n", $conn );
                printf( "App        : %-15s  \n", $app );
                printf( "Production : %-15s  \n", $prod );
                printf( "Back Sched : %-15s  \n", $backschd );
                printf( "Audit      : %-15s  \n", $audit );
                printf( "Live       : %-15s  \n", $live );
            }
            else{ 
                printf( "Error attempting to find database\n" );
                Configure('database',0);
            }
            printf( "..............................\n" );
            printf( "Back (Cancel)              (0)\n" );
            printf( "Confirm                    (1)\n" );
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure('database', 0); }
            elsif( $input == 1 ){
                $rowcount = $gDBH->do( "update db_key set live = '0', audit = '0' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Database is no longer live.\n" );
            }
        }
    }
    elsif( @_[0] eq 'cli_sys' ){
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Modify System CLI mode\n" ); };
        printf( "Modify system\n..............................\n" );
        # Get and check hostname
        printf( "Back                       (0)\n" );
        printf( "Select host from list      (1)\n" );
        printf( "Search for host by name    (2)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('system', 0); }
        if( $input == 1 ){ $hostname = ""; }
        elsif( $input == 2 ){
            $input = Prompt_User( "Hostname", "localhost", "hostname" );
            if( DEBUG == 1 ){ printf( "Returned $input for hostname\n" ); }
            if( $input =~ /^[0]+$/ ){
                Configure('system', 0);
            }
            elsif( $input == FAILED ){
                Modify_Record('cli_sys');
            }
            else{
                $hostname = $input;
            }
        }

        # All options that pass through should get here:
        printf( "Back                       (0)\n" );
        Show_Systems('menu',10,$hostname);
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('system', 0); }
        else{
            $hkey = $input;
            $sql = "select hostname from host_key where hkey = $hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];                
            }
            if( $sth->rows() > 0 ){ printf( "Will be using $hostname\n" ); }
            else{ 
                printf( "Error attempting to find system\n" );
                Configure('system',0);
            }

            $sql = "select k.hostname, h.ip, h.virtual, h.os, h.osver, h.san, h.cluster, h.owner, k.audit, k.live from host_key k, host_info h where h.hkey = $hkey and k.hkey = h.hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];
                $ip       = $rows[1];
                $virtual  = $rows[2];
                $os       = $rows[3];
                $osver    = $rows[4];
                $san      = $rows[5];
                $cluster  = $rows[6];
                $owner    = $rows[7];
                $audit    = $rows[8];
                $live     = $rows[9];
            }

            if( $sth->rows() > 0 ){ 
                # Display current values
                printf( "\nChoose field to change:\n..............................\n");
                printf( "Back (Cancel)              (0)\n" );
                printf( "Hostname: %-15s  (1)\n", $hostname );
                printf( "IP      : %-15s  (2)\n", $ip );
                printf( "Virtual : %-15s  (3)\n", $virtual );
                printf( "OS      : %-15s  (4)\n", $os );
                printf( "OS ver  : %-15s  (5)\n", $osver );
                printf( "SAN     : %-15s  (6)\n", $san );
                printf( "Cluster : %-15s  (7)\n", $cluster );
                printf( "Owner   : %-15s  (8)\n", $owner );
                printf( "Audited : %-15s  (9)\n", $audit );
                printf( "Live    : %-15s  (10)\n", $live );
            }
            else{ 
                printf( "Error attempting to find system\n" );
                Configure('system',0);
            }
            printf( "..............................\n" );
            $input = Prompt_User("choice","0","num");
            # This has been stripped down pretty tight
            if( $input == 0 ){ Configure('system', 0); }
            elsif( $input == 1 ){
                $input = Prompt_User( "Hostname", "$hostname", "hostname" );
                if( DEBUG == 1 ){ printf( "Returned $input for hostname\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($hostname = $input);
                $rowcount = $gDBH->do( "update host_key set hostname = '$hostname' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                $rowcount = $gDBH->do( "update host_info set hostname = '$hostname' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Hostname updated\n" );
            }
            elsif( $input == 2 ){ 
                $input = Prompt_User( "IP Address", "$ip", "ip" );
                if( DEBUG == 1 ){ printf( "Returned $input for IP\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($hostname = $input);
                $rowcount = $gDBH->do( "update host_info set ip = '$hostname' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "IP Address updated\n" );
            }
            elsif( $input == 3 ){
                # Set the y/n to bool 0/1 and back
                $virtual eq '1' ? ($virtual = 'y') : ($virtual = 'n');
                $input = Prompt_User( "Virtualized", "$virtual", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for IP\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($virtual = $input);
                $virtual eq 'y' ? ($virtual = 1) : ($virtual = 0);
                $rowcount = $gDBH->do( "update host_info set virtual = '$virtual' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Virtual updated\n" );
            }
            elsif( $input == 4 ){ 
                $input = Prompt_User( "OS (optional)", "$os", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for OS\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($os = $input);
                $rowcount = $gDBH->do( "update host_info set os = '$os' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "OS updated\n" );
            }
            elsif( $input == 5 ){ 
                $input = Prompt_User( "OS Version (optional)", "$osver", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for OS Version\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($osver = $input);
                $rowcount = $gDBH->do( "update host_info set osver = '$osver' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "OS Version updated\n" );
            }
            elsif( $input == 6 ){ 
                $input = Prompt_User( "SAN (optional)", "$san", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for SAN\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($san = $input);
                $rowcount = $gDBH->do( "update host_info set san = '$san' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "SAN updated\n" );;
            }
            elsif( $input == 7 ){ 
                $input = Prompt_User( "Cluster (optional)", "$cluster", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for Cluster\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($cluster = $input);
                $rowcount = $gDBH->do( "update host_info set cluster = '$cluster' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Cluster updated\n" );
            }
            elsif( $input == 8 ){ 
                $input = Prompt_User( "Owner (optional)", "$owner", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for Owner\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($owner = $input);
                $rowcount = $gDBH->do( "update host_info set owner = '$owner' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Owner updated\n" );
            }
            elsif( $input == 9 ){ 
                # Set the y/n to bool 0/1 and back
                $audit eq '1' ? ($audit = 'y') : ($audit = 'n');
                $input = Prompt_User( "Audited", "$audit", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for Audit\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($audit = $input);
                $audit eq 'y' ? ($audit = 1) : ($audit = 0);
                $rowcount = $gDBH->do( "update host_key set audit = '$audit' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Audit updated\n" );
            }
            elsif( $input == 10 ){ 
                # Set the y/n to bool 0/1 and back
                $live eq '1' ? ($live = 'y') : ($live = 'n');
                $input = Prompt_User( "Live", "$live", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for Live\n" ); }
                $input == FAILED ? (Configure('system', 0)) : ($live = $input);
                $live eq 'y' ? ($live = 1) : ($live = 0);
                $rowcount = $gDBH->do( "update host_key set live = '$live' where hkey = $hkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Live updated\n" );
            }
            else{
                printf("Unsupported option\n");
                Configure('system', 0);
            }

            # If we're here, we've run an update statement. Confirm.
            $sql = "select k.hostname, i.ip, i.virtual, i.os, i.osver, i.san, i.cluster, i.owner, k.audit, k.live from host_key k, host_info i where i.hkey = $hkey and k.hkey = i.hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];
                $ip       = $rows[1];
                $virtual  = $rows[2];
                $os       = $rows[3];
                $osver    = $rows[4];
                $san      = $rows[5];
                $cluster  = $rows[6];
                $owner    = $rows[7];
                $audit    = $rows[8];
                $live     = $rows[9];
            }
            printf( "..............................\n" );
            printf( "Back                       (0)\n" );

            if( $sth->rows() > 0 ){ 
                # Display current values
                printf( "\nValues have been updated\n..............................\n");
                printf( "Hostname: %-15s  \n", $hostname );
                printf( "IP      : %-15s  \n", $ip );
                printf( "Virtual : %-15s  \n", $virtual );
                printf( "OS      : %-15s  \n", $os );
                printf( "OS ver  : %-15s  \n", $osver );
                printf( "SAN     : %-15s  \n", $san );
                printf( "Cluster : %-15s  \n", $cluster );
                printf( "Owner   : %-15s  \n", $owner );
                printf( "Audited : %-15s  \n", $audit );
                printf( "Live    : %-15s  \n", $live );
            }
            else{ 
                printf( "Error attempting to update system\n" );
            }
        }
    }
    elsif( @_[0] eq 'cli_db' ){
        if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Modify Database CLI mode\n" ); };
        printf( "Modify database\n..............................\n" );
        # Get and check dbname
        printf( "Back                       (0)\n" );
        printf( "Select db from list        (1)\n" );
        printf( "Search for db by name      (2)\n" );
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('database', 0); }
        if( $input == 1 ){ $dbname = ""; }
        elsif( $input == 2 ){
            $input = Prompt_User( "Database Name", "default", "" );
            if( DEBUG == 1 ){ printf( "Returned $input for dbname\n" ); }
            if( $input =~ /^[0]+$/ ){
                Configure('database', 0);
            }
            elsif( $input == FAILED ){
                Modify_Record('cli_db');
            }
            else{
                $dbname = $input;
            }
        }

        # All options that pass through should get here:
        printf( "Back                       (0)\n" );
        Show_Databases('menu',10,$dbname);
        printf( "..............................\n" );
        $input = Prompt_User("choice","0","num");
        if( $input == 0 ){ Configure('databases', 0); }
        else{
            $dkey = $input;
            $sql = "select dbname from db_key where dkey = $dkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $dbname = $rows[0];                
            }
            if( $sth->rows() > 0 ){ printf( "Will be using $dbname\n" ); }
            else{ 
                printf( "Error attempting to find database\n" );
                Configure('database',0);
            }

            $sql = "select h.hostname, d.dbname, d.rdbms, d.instance, d.cluster, d.connstring, d.app, d.production, d.owner, d.comments, d.backupsched, k.audit, k.live from host_key h, db_key k, db_info d where k.dkey = $dkey and k.dkey = d.dkey and h.hkey = d.hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];
                $dbname   = $rows[1];
                $rdbms    = $rows[2];
                $instance = $rows[3];
                $cluster  = $rows[4];
                $conn     = $rows[5];
                $app      = $rows[6];
                $prod     = $rows[7];
                $owner    = $rows[8];
                $comments = $rows[9];
                $backschd = $rows[10];
                $audit    = $rows[11];
                $live     = $rows[12];
            }

            if( $sth->rows() > 0 ){ 
                # Display current values
                printf( "\nChoose field to change:\n..............................\n");
                printf( "Back (Cancel)              (0)\n" );
                printf( "Hostname   : %-13s (1)\n", $hostname );
                printf( "DB Name    : %-13s (2)\n", $dbname );
                printf( "RDBMS      : %-13s (3)\n", $rdbms );
                printf( "Instance   : %-13s (4)\n", $instance );
                printf( "Cluster    : %-13s (5)\n", $cluster );
                printf( "Connstr    : %-13s (6)\n", $conn );
                printf( "App        : %-13s (7)\n", $app );
                printf( "Production : %-13s (8)\n", $prod );
                printf( "Owner      : %-13s (9)\n", $owner );
                printf( "Comments   : %-13s (10)\n", $comments );
                printf( "Back Sched : %-13s (11)\n", $backschd );
                printf( "Audit      : %-13s (12)\n", $audit );
                printf( "Live       : %-13s (13)\n", $live );
            }
            else{ 
                printf( "Error attempting to find database\n" );
                Configure('database',0);
            }
            printf( "..............................\n" ); 
            $input = Prompt_User("choice","0","num");
            if( $input == 0 ){ Configure('databases', 0); }
            # This has been stripped down pretty tight
            if( $input == 0 ){ Configure('system', 0); }
            elsif( $input == 1 ){
                # Get and check hostname. I seem to use this a lot
                printf( "Back                       (0)\n" );
                printf( "Select host from list      (1)\n" );
                printf( "Search for host by name    (2)\n" );
                printf( "..............................\n" );
                $input = Prompt_User("choice","0","num");
                if( $input == 0 ){ Configure('database', 0); }
                if( $input == 1 ){ $hostname = ""; }
                elsif( $input == 2 ){
                    $input = Prompt_User( "Hostname", "localhost", "hostname" );
                    if( DEBUG == 1 ){ printf( "Returned $input for hostname\n" ); }
                    if( $input =~ /^[0]+$/ ){
                        Configure('database', 0);
                    }
                    elsif( $input == FAILED ){ Modify_Record('cli_db'); }
                    else{ $hostname = $input; }
                }

                # All options that pass through should get here:
                printf( "Back                       (0)\n" );
                Show_Systems('menu',10,$hostname);
                printf( "..............................\n" );
                $input = Prompt_User("choice","0","num");
                if( $input == 0 ){ Configure('database', 0); }
                else{
                    $hkey = $input;
                    $sql = "select hostname from host_key where hkey = $hkey";
                    if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
                    $sth = $gDBH->prepare($sql)
                        or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                    $sth->execute();
                    while( @rows = $sth->fetchrow_array() ){
                        $hostname = $rows[0];                
                    }
                    if( $sth->rows() > 0 ){ printf( "Will be using $hostname\n" ); }
                    else{ 
                        printf( "Error attempting to find system\n" );
                        Configure('database',0);
                    }
                }
                $rowcount = $gDBH->do( "update db_info set hkey = $hkey where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Hostname updated \nNote: Verify the Connect string!\n" );
            }
            elsif( $input == 2 ){ 
                $input = Prompt_User( "DB Name", "$dbname", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for DBName\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($dbname = $input);
                $rowcount = $gDBH->do( "update db_key set dbname = '$dbname' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                $rowcount = $gDBH->do( "update db_info set dbname = '$dbname' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "DB Name updated\n" );
            }
            elsif( $input == 3 ){ 
                $input = Prompt_User( "RDBMS", "$rdbms", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for RDBMS\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($rdbms = lc($input));
                $rowcount = $gDBH->do( "update db_info set rdbms = '$rdbms' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "RDBMS updated\n" );
            }
            elsif( $input == 4 ){ 
                $input = Prompt_User( "Instance", "$instance", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for instance\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($instance = $input);
                $rowcount = $gDBH->do( "update db_info set instance = '$instance' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Instance updated \nNote: Verify the Connect string!\n" );
            }
            elsif( $input == 5 ){ 
                $input = Prompt_User( "Cluster (optional)", "$cluster", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for cluster\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($cluster = $input);
                $rowcount = $gDBH->do( "update db_info set cluster = '$cluster' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Cluster updated \nNote: Verify the Connect string!\n" );
            }
            elsif( $input == 6 ){ 
                $input = Prompt_User( "Connection string", "$conn", "uri" );
                if( DEBUG == 1 ){ printf( "Returned $input for connstring\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($conn = $input);
                $rowcount = $gDBH->do( "update db_info set connstring = '$conn' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Connection string updated\n" );
            }
            elsif( $input == 7 ){ 
                $input = Prompt_User( "Application (optional)", "$app", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for app\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($app = $input);
                $rowcount = $gDBH->do( "update db_info set app = '$app' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Application updated\n" );
            }
            elsif( $input == 8 ){
                # Set the y/n to bool 0/1 and back
                $prod eq '1' ? ($prod = 'y') : ($prod = 'n');
                $input = Prompt_User( "Production", "$prod", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for production\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($prod = $input);
                $prod eq 'y' ? ($prod = 1) : ($prod = 0);
                $rowcount = $gDBH->do( "update db_info set production = '$prod' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Production updated\n" );
            }
            elsif( $input == 9 ){ 
                $input = Prompt_User( "Owner (optional)", "$owner", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for owner\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($owner = $input);
                $rowcount = $gDBH->do( "update db_info set owner = '$owner' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Owner updated\n" );
            }
            elsif( $input == 10 ){ 
                $input = Prompt_User( "Comments (optional)", "$comments", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for comments\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($comments = $input);
                $rowcount = $gDBH->do( "update db_info set comments = '$comments' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Comments updated\n" );
            }
            elsif( $input == 11 ){ 
                $input = Prompt_User( "Backup Schedule (optional)", "$backschd", "" );
                if( DEBUG == 1 ){ printf( "Returned $input for backup schedule\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($backschd = $input);
                $rowcount = $gDBH->do( "update db_info set backupsched = '$backschd' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Backup schedule updated\n" );
            }
            elsif( $input == 12 ){
                # Set the y/n to bool 0/1 and back
                $audit eq '1' ? ($audit = 'y') : ($audit = 'n');
                $input = Prompt_User( "Audited", "$audit", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for audit\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($audit = $input);
                $audit eq 'y' ? ($audit = 1) : ($audit = 0);
                $rowcount = $gDBH->do( "update db_key set audit = '$audit' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Audit updated\n" );
            }
            elsif( $input == 13 ){
                # Set the y/n to bool 0/1 and back
                $live eq '1' ? ($live = 'y') : ($live = 'n');
                $input = Prompt_User( "Live", "$live", "bool" );
                if( DEBUG == 1 ){ printf( "Returned $input for live\n" ); }
                $input == FAILED ? (Configure('database', 0)) : ($live = $input);
                $live eq 'y' ? ($live = 1) : ($live = 0);
                $rowcount = $gDBH->do( "update db_key set live = '$live' where dkey = $dkey" )
                    or Fail_Out("Unable to update $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
                printf( "Live updated\n" );
            }
            else{
                printf( "Unsupported Option\n" );
                Configure('database',0);
            }
            #If we're here, we've completed an update.
            $sql = "select h.hostname, d.dbname, d.rdbms, d.instance, d.cluster, d.connstring, d.app, d.production, d.owner, d.comments, d.backupsched, k.audit, k.live from host_key h, db_key k, db_info d where k.dkey = $dkey and k.dkey = d.dkey and h.hkey = d.hkey";
            if( DEBUG == 1 ){ printf( "Running query: $sql\n" ); }
            $sth = $gDBH->prepare($sql)
                or Fail_Out("Unable to query $ghConfig{'opt'}{'intdbname'}: $DBI::errstr\n");
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                $hostname = $rows[0];
                $dbname   = $rows[1];
                $rdbms    = $rows[2];
                $instance = $rows[3];
                $cluster  = $rows[4];
                $conn     = $rows[5];
                $app      = $rows[6];
                $prod     = $rows[7];
                $owner    = $rows[8];
                $comments = $rows[9];
                $backschd = $rows[10];
                $audit    = $rows[11];
                $live     = $rows[12];
            }

            if( $sth->rows() > 0 ){ 
                # Display current values
                printf( "\nValues have been updated\n..............................\n");
                printf( "Hostname   : %-13s\n", $hostname );
                printf( "DB Name    : %-13s\n", $dbname );
                printf( "RDBMS      : %-13s\n", $rdbms );
                printf( "Instance   : %-13s\n", $instance );
                printf( "Cluster    : %-13s\n", $cluster );
                printf( "Connstr    : %-13s\n", $conn );
                printf( "App        : %-13s\n", $app );
                printf( "Production : %-13s\n", $prod );
                printf( "Owner      : %-13s\n", $owner );
                printf( "Comments   : %-13s\n", $comments );
                printf( "Back Sched : %-13s\n", $backschd );
                printf( "Audit      : %-13s\n", $audit );
                printf( "Live       : %-13s\n", $live );
            }
            else{ 
                printf( "Error attempting to find database\n" );
                Configure('database',0);
            }
        }
    }
    else{
        # TODO: Add the batch and web-driven modes
    } 
}
#/********************** End of Modify_Record sub ****************************/ 


#/****************************************************************************/
#/*  Do the actual server insert. We insert the host_key, then the host_info**/
#/****************************************************************************/
sub Create_System{
    my( $hostname, $ip, $virtual, $os, $osver, $san, $cluster, $owner, $audit, $live ) = @_;
    my( @rows, $hkey );
    # First create host_key, then get the key and create the host_info
    # Doing this in an eval because there can be a ton of errors
    # based on constraints, duplicates, etc. Want to catch them.
    # This seems messy - TODO: Clean up
    my $sql = "insert into host_key (hostname, audit, live) values( '$hostname', $audit, $live )";
    if( DEBUG == 1 ){ printf( "Creating Host Key: $sql\n" ); }
    eval{
        my $rownum = $gDBH->do($sql);
        my $sth_host = $gDBH->prepare( "insert into host_info (hkey, hostname, ip, virtual, os, osver, san, cluster, owner) values( ?, '$hostname', '$ip', $virtual, '$os', '$osver', '$san', '$cluster', '$owner')" );
        
        if( $rownum ){
            if( DEBUG == 1 ){ printf( "Checking Host Key: $rownum rows added\n" ); }
            $sql = "select hkey, hostname from host_key where hostname = '$hostname'";
            my $sth = $gDBH->prepare($sql);
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                if( DEBUG == 1 ){ printf( "New Host Key: '$rows[0],$rows[1]' added\n" ); }
                $hkey = $rows[0];
            }

            if( $sth->rows() > 0 ){
                if( DEBUG == 1 ){ printf( "Creating Host: insert into host_info (hkey, hostname, ip, virtual, os, osver, san, cluster, owner) values( $hkey, '$hostname', '$ip', $virtual, '$os', '$osver', '$san', '$cluster', '$owner')\n" ); }
                $sth_host->execute($rows[0])
                    or Fail_Out( "Error creating Host" );
            }
            else{
                if( DEBUG == 1 ){ Fail_Out( "Error creating host_info" ); }
            }
        }
        else{
            if( DEBUG == 1 ){ Fail_Out( "Error creating host_key: $DBI::errstr" ); }
        }
    }; Fail_Out( "Error inserting new host $@, $DBI::errstr" ) if $@;

    # Done, confirm
    printf( "\nSystem created\n" );
    printf( "Host Key: $hkey\n" );
    printf( "Hostname: $hostname\n" );
    printf( "IP      : $ip\n" );
    printf( "Virtual : $virtual\n" );
    printf( "OS      : $os\n" );
    printf( "OS ver  : $osver\n" );
    printf( "SAN     : $san\n" );
    printf( "Cluster : $cluster\n" );
    printf( "Owner   : $owner\n" );
    printf( "Audited : $audit\n" );
    printf( "Live    : $live\n" );
}
#/*********************** End of Create_System sub ***************************/


#/****************************************************************************/
#/*  Do the actual db insert. We insert the db_key, then the db_info        **/
#/****************************************************************************/
sub Create_Database{
    my( $hkey, $dbname, $rdbms, $instance, $cluster, $connstring, $app, $prod, $owner, $comments, $backupsched, $audit, $live ) = @_;
    #printf( "Got $hkey, $dbname, $rdbms, $instance, $cluster, $connstring, $app, $prod, $owner, $comments, $backupsched, $audit, $live \n" );
    my( @rows, $dkey );
    # First create db_key, then get the key and create the db_info
    # Doing this in an eval because there can be a ton of errors
    # based on constraints, duplicates, etc. Want to catch them.
    # Now, MSSQL uses a whole host of default databases and default as the default instance
    # To work around this, db_key can't have a unique dbname. Silly, but that's why.
    # We try to grab the most recent db_key and hope not to have concurrency problems
    # This seems messy - TODO: Clean up
    my $sql = "insert into db_key (dbname, audit, live) values( '$dbname', $audit, $live )";
    if( DEBUG == 1 ){ printf( "Creating DB Key: $sql\n" ); }
    eval{
        my $rownum = $gDBH->do($sql);
        my $sth_db = $gDBH->prepare( "insert into db_info (hkey, dkey, dbname, rdbms, instance, cluster, connstring, app, production, owner, comments, backupsched) values( $hkey, ?, '$dbname', '$rdbms', '$instance', '$cluster', '$connstring', '$app', '$prod', '$owner', '$comments', '$backupsched')" );
        
        if( $rownum ){
            if( DEBUG == 1 ){ printf( "Checking DB Key: $rownum rows added\n" ); }
            $sql = "select dkey, dbname from db_key where dbname = '$dbname'";
            my $sth = $gDBH->prepare($sql);
            $sth->execute();
            while( @rows = $sth->fetchrow_array() ){
                if( DEBUG == 1 ){ printf( "New DB Key: '$rows[0],$rows[1]' added\n" ); }
                $dkey = $rows[0];
            }

            if( $sth->rows() > 0 ){
                if( DEBUG == 1 ){ printf( "Creating DB: insert into db_info (hkey, dkey, dbname, rdbms, instance, cluster, connstring, app, production, owner, comments, backupsched) values( $hkey, $dkey, '$dbname', '$rdbms', '$instance', '$cluster', '$connstring', '$app', '$prod', '$owner', '$comments', '$backupsched')\n" ); }
                $sth_db->execute($rows[0])
                    or Fail_Out( "Error creating Database" );
            }
            else{
                if( DEBUG == 1 ){ Fail_Out( "Error creating db_info" ); }
            }
        }
        else{
            if( DEBUG == 1 ){ Fail_Out( "Error creating db_key: $DBI::errstr" ); }
        }
    }; Fail_Out( "Error inserting new db $@, $DBI::errstr" ) if $@;

    # Done, confirm
    printf( "\nDatabase created\n" );
    printf( "DB Name    : $dbname\n" );
    printf( "RDBMS      : $rdbms\n" );
    printf( "Instance   : $instance\n" );
    printf( "Cluster    : $cluster\n" );
    printf( "Connection : $connstring\n" );
    printf( "Application: $app\n" );
    printf( "Production : $prod\n" );
    printf( "Owner      : $owner\n" );
    printf( "Comments   : $comments\n" );
    printf( "Backup Schd: $backupsched\n" );
    printf( "Audited    : $audit\n" );
    printf( "Live       : $live\n" );
}
#/********************* End of Create_Database sub ***************************/


#/****************************************************************************/
#/*  Prompt handler. Expects the user prompt and an optional default.       **/
#/*  Returns constant FAILED or a checked alphanum value                    **/
#/****************************************************************************/
sub Prompt_User{
    my( $prompt, $default, $filter ) = @_;
    if( $default ne "" ){
        printf( "$prompt [$default]: " );
    }
    else{
        printf( "$prompt: " );
    }
    chomp( my $input = <STDIN> );

    # Basic garbage filter - accepts alphanum + hostnames and such
    if( $input ne "" ){
        if( $filter eq 'hostname' ){
            if( $input =~ /^[a-zA-Z0-9.-]+$/ ){
                return( $input );
            }
            else{
                printf( "Invalid input, please try again\n" );
                return( FAILED );
            }
        }
        elsif( $filter eq 'uri' ){
            if( $input =~/^[\d\w.\/-:\\]+$/ ){
                return( $input );
            }
            else{
                printf( "Invalid input, please try again\n" );
                return( FAILED );
            }
        }
        elsif( $filter eq 'ip' ){
            if( $input =~ /^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$/ ){
                return( $input );
            }
            else{
                printf( "Invalid input, please try again\n" );
                return( FAILED );
            }
        }
        elsif( $filter eq 'num' ){
            if( $input =~ /^[0-9]+$/ ){
                return( $input );
            }
            else{
                printf( "Invalid input, please try again\n" );
                return( FAILED );
            }
        }
        elsif( $filter eq 'alpha' ){
            if( $input =~ /^[a-zA-Z]+$/ ){
                return( $input );
            }
            else{
                printf( "Invalid input, please try again\n" );
                return( FAILED );
            }
        }
        elsif( $filter eq 'bool' ){
            if( lc($input) =~ /[y]|[yes]/ ){
                return( "y" );
            }
            elsif( lc($input) =~ /[n]|[no]/ ){
                return( "n" );
            } 
            else{
                printf( "Invalid input, please try again\n" );
                return( FAILED );
            }
        }
        else{
            # Apply very basic check - alphanumeric, ':', '-' and '.'
            if( $input =~ /^[\w\d\s-.:]+$/ ){
                return( $input );
            }
            else{
                printf( "Invalid input, please try again\n" );
                return( FAILED );
            }
        }
    }
    else{
        return( $default );
    }
}
#/************************ End of Prompt_User sub ****************************/

#/****************************************************************************/
#/*  Scrub database inputs                                                  **/
#/*  This will default to returning FAILED, but can be set to return null   **/
#/****************************************************************************/
sub Scrub_SQL{
    if( @_[0] ){
        if( @_[0] =~/^[\d\w.\/\s-:\\,]+$/ ){
            return( @_[0] );
        }
        else{
            if( (DEBUG == 1) || ($ghConfig{'arg'}{'verbose'} == 1) ){ printf( "Invalid SQL value passed, please try again: @_[0]\n" ); }
            @_[1] eq "" ? (return(FAILED)) : (return( "" ));
        }
    }
    else{ return( "" ); }
}
#/************************* End of Scrub_SQL sub *****************************/


#/****************************************************************************/
#/*  Handle the abortive exit of the program. Make sure that it all exits   **/
#/* in a nice, pretty, and useful fashion. Free up memory/resources if req. **/
#/****************************************************************************/
sub Fail_Out{
    foreach( @_ ){
        push( @gaMessages, $_ );
    }
    
    printf( "@gaMessages\n" );
    exit;
}
#/*************************** End of Fail_Out sub ****************************/
