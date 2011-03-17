#!/usr/bin/perl

###############################################################################
#                                                                             
#                              heron-feeder.pl                                
#                          usage: heron-feeder.pl
#  This produces JSON files for the Heron Dashboard to read in small-scale 
# non-DB driven implementations
#
#  Copyright (c) 2009, Mike Bybee All rights reserved.                         
# Redistribution and use in source and binary forms, with or without          
# modification, are permitted provided that the following conditions are met:  
# Redistributions of source code must retain the above copyright notice, this  
# list of conditions and the following disclaimer.                            
#                                                                             
#  Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and
# /or other materials provided with the distribution. Neither the name of the 
# organization nor the names of its contributors may be used to endorse or 
# promote products derived from this software without specific prior written 
# permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE. 
#
#  You may obtain a copy of the License at:
#                http://mbybee.net/dashboard/LICENSE.html
###############################################################################



# Known Issues:
# * Optimize. There is always room for speed improvements.
# * Several oddities and quirks - look for notes.
# * Redundant variables in several places due to 'fast and loose' POC
# * Add hook to use the DBI::Oracle module (though most people don't have it)
# * Finish putting in the config file stuff, including the encrypted passwd

###############################################################################
# Globals
#
use strict;
use POSIX;
use Getopt::Long;
use Crypt::CBC;
use Crypt::Blowfish;
require POSIX;
require Getopt::Long;
require Crypt::CBC;
require Crypt::Blowfish;

my @gaMessages;
my $gcKEY = '1JajdipfleLDK!$sodua_*I3[kks993sjhndlqurpopvhhule,019-329';
my $gcCipher = new Crypt::CBC($gcKEY,'Blowfish');
#my $crypt = $gcCipher->encrypt("1");
#my $decrypt = $gcCipher->decrypt($crypt);
#printf( "Password test became: \n\t$crypt\n\t$decrypt\n" );
my $gcInput;
my %ghParams;
my $gcSUCCEEDED = 0;
my $gcFAILED = -1;
my $gcRC;
my $gcLogPath = "";
my $gcLog = "$gcLogPath/heron-feeder.log";
my $gcCONFIG = "$gcLogPath/heron-feeder.config";
my $gcTRUE = 1;
my $gcFALSE = 0;
my $gcVERSION = "Heron-Feeder Version 0.01\nCopyright (c) 2009, Mike Bybee All rights reserved. \nReleased under the terms of the BSD-Simplified license at \nhttp://mbybee.net/dashboard/LICENSE.html\n";
my $gcHELP = "Usage: heron-feeder.pl \n";

my %ghGauge = (
    "GAUGEDATA" => (
        {
	    "SCALE"   => 0,
            "STARTVAL"=> 0,
	    "ENDVAL"  => 0
        }
    )
);
my %ghChart = (
    "LAYOUT"  => (
	{
	    "MINVAL"  => 0,
	    "MAXVAL"  => 100
	}
    ),
    "VAL1"    => (
	{
	    "LABEL"   => "TEMP",
	    "SCALE"   => 1,
	    "DP1"     => "JUNE",
	    "DP2"     => "JULY",
	    "DP3"     => "AUGUST",
	    "DP1VAL"  => 0,
	    "DP2VAL"  => 0,
	    "DP3VAL"  => 0
	}
    )
);





# System Specific Stuff
my $gcMail = '/usr/bin/mailx -s "Heron Feeder" admin@local';
my $gcCopyCmd = "cp ";
my $gcProfile = "/export/home/oraoem/.profile";
#my $gcDF = "/usr/bin/df -k $gcPath |tail -1";
my $gcDF = "fsutil volume diskfree C:";

# Timestamp stuff for the log
my @gaTIME = localtime(time);
#    The date formatting stuff (for reference)
#printf( "@gaTIME\n");
#my $test = POSIX::strftime( "%a %A %b %B %c %d %H %I %j %m %M %p %S %U %w %W %x %X %y %Y %Z", @gaTIME );
#print( "Time: $test\n" );
my $gcDate_Time = POSIX::strftime( "%x - %H:%M", @gaTIME );

#
# End of Globals
###############################################################################





###############################################################################
# Main
#

# Check Input
Usage();

#
# Open Log and being running checks
#
open( goutLog, ">> $gcLogPath$gcLog" )
    or Fail_Out( "Could not open log file: $gcLog $!\n" );

if( $ghParams{'SPACE'} = $gcTRUE ){
    #Check_Space();
}
if( $ghParams{'DBTYPE'} ne "NODB" ){
    Check_Database();
}




#
# End Program
#
close( goutLog );
exit;













###############################################################################
# Subroutines
#

################################################################################
# Parse the input parameters, and print usage info if needed
# 
sub Usage{
    my( $verbose, $database, $dbtype, $dbname, $light, $format, $exclude, $repository,
        $optionfile, $help, $version, $configure, $space);

    # The Getopt::Long automatically handles both - and --, as well as allowing
    # the very minimum number of unique characters. Both v and verbose would be
    # equiv and not require me to break them out.   

    # Note: Database support the -nodb option. If -nodb is specified AND dbtype
    # is specified, we'll ignore nodb. If database is specified without a type
    # we default to Oracle. If just -nodatabase or no db stuff, we'll skip db
    # related checks.
    GetOptions(
        "verbose" => \$verbose,
        "database!" => \$database,
        "dbtype=s" => \$dbtype,
	"dbname=s" => \$dbname,
        "light" => \$light,
        "format=s" => \$format,
        "exclude" => \$exclude,
        "repository=s" => \$repository,
        "optionfile" => \$optionfile,
	"help|?" => \$help,
	"version|about" => \$version,
	"configure|reconfigure" => \$configure,
	"space|disk" => \$space
    );
    if( $version ){
	printf( "$gcVERSION\n" );
	exit;
    }
    if( $help ){
	printf( "$gcHELP\n" );
	exit;
    }
    if( $verbose ){
        printf( "You wanted VERBOSE\n" );
        $ghParams{'VERBOSE'} = $gcTRUE;
    }
    if( $configure ){
	printf( "Configuration Mode\n" );
	Configure_System();
    }
    if( $space ){
	printf( "You want to check space\n" );
	$ghParams{'SPACE'} = $gcTRUE;
    }
    if( $light ){
        $ghParams{'LIGHT'} = $gcTRUE;
        printf( "You want it LIGHT\n" );
    }
    if( $format ){
        printf( "You want it FORMATED\n" );
	$ghParams{'FORMAT'} = uc($format);
        printf( "Using $format format\n" );
    }
    if( $database && $dbtype ){
        printf( "You want to monitor a database of type $dbtype\n" );
	$ghParams{'DBTYPE'} = uc($dbtype); 
    }elsif( $dbtype ){
	printf( "Monitoring $dbtype\n" );
	$ghParams{'DBTYPE'} = uc($dbtype);
    }elsif( $database ){
	printf( "No dbtype specified. Assuming Oracle\n" );
	$ghParams{'DBTYPE'} = 'ORACLE';
	$dbtype = 'ORACLE';
    }else{
	printf( "Either no db switches, or -nodb\n" );
	$ghParams{'DBTYPE'} = 'NODB';
    }
    
    # Check to see if we specific a type, but no database name. Try the default
    if( $dbtype && $dbname ){
	# Database names can be case sensitive
	$ghParams{'DBNAME'} = $dbname;
	printf( "Will use $dbtype database $ghParams{'DBNAME'}\n" );
    }elsif( ($ghParams{'DBTYPE'} eq "ORACLE") && ($ENV{'ORACLE_SID'}) ){
        $ghParams{'DBNAME'} = $ENV{'ORACLE_SID'};
    }elsif( ($ghParams{'DBTYPE'} eq "DB2") && ($ENV{'DB2INSTANCE'}) ){
        $ghParams{'DBNAME'} = $ENV{'DB2INSTANCE'};
    }elsif( ($ghParams{'DBTYPE'} eq "MYSQL") && ($ENV{'MYSQL_HOST'}) ){
        $ghParams{'DBNAME'} = $ENV{'MYSQL_HOST'};
    }elsif( $ghParams{'DBTYPE'} eq "MSSQL" ){
	#$ghParams{'DBNAME'} = $ENV{''};
	#No idea - need to check
    }else{
	printf( "No value for dbname. Unable to determine from environment.\n" );
    }

    if( $ghParams{'DBNAME'} ){
	# Check the config file for the database connect information
	# NOTE - WORKING ON THIS PART
	printf( "Unable to determine connection information for $ghParams{'DBNAME'} from config file\n" );
	printf( "Database name = $ghParams{'DBNAME'} (y/n): " );
        chomp($gcInput = <STDIN>);
	if( lc($gcInput) eq "n" ) {
	    printf( "\nEnter new Database name: " );
	    chomp($gcInput = <STDIN>);
	    $ghParams{'DBNAME'} = $gcInput;
	    printf( "\nDatabase name now $ghParams{'DBNAME'}\n" );
        }

	printf( "Enter Database user: " );
	chomp($gcInput = <STDIN>);
	$ghParams{'DBUSER'} = $gcInput;
	printf( "\nDatabase user now $ghParams{'DBUSER'}\n" );

	printf( "Enter Database password: " );
	chomp($gcInput = <STDIN>);
	$ghParams{'DBPASS'} = $gcInput;
        
	printf( "Store this data in the config file? The password will be encrypted. (y/n): " );
	chomp($gcInput = <STDIN>);
	if( lc($gcInput) eq "y" ){
	    my $crypt = $gcCipher->encrypt($ghParams{'DBPASS'});
	    printf( "\nWritten to config file blah as $crypt\n" );
	}
    }
    #printf( "Will use $dbtype database : $ghParams{'DBNAME'}\n" );

    # Check values and throw it back if any include a -
    foreach ( keys %ghParams ){
	if( $ghParams{$_} =~ m/^\-/ ){
	    Fail_Out( "Invalid option passed to $_: $ghParams{$_}" );
	}
    }

}
#
# End of Usage Sub
###############################################################################


###############################################################################
#  Handle the abortive exit of the program. Make sure that it all exits
# in a nice, pretty, and useful fashion. Free up memory/resources if req.
#
sub Fail_Out{
    foreach( @_ ){
        push( @gaMessages, $_ );
    }
    
    printf( "@gaMessages\n" );
    #printf goutLog ( "$gcDate_Time -FAILURE-\n @gaMessages\n -FAILURE-" );
    exit;
}
# 
# End of Fail_Out sub
###############################################################################


###############################################################################
#  Set up the configuration file (holds passwords/connectstrings etc)
#
sub Configure_System{

}
#
# End of Configure_System sub
###############################################################################


###############################################################################
#  Run Database Checks. This calls all the general checks, and uses the Run_SQL
#  sub to generate and specific calls or queries as needed for a database.
#
sub Check_Database{
    Run_SQL('SPACE');
    Run_SQL('CURRENTUSERS');
}
#
# End of Configure_System sub
###############################################################################




###############################################################################
#  Run SQL, based on the the dbtype query, and made specific to the database
#  needed. This handles all the specific/specialized translations and syntax
#  Note: %%Oracle is needed because Perl interprets %O and \%O as octal
#
sub Run_SQL{
    my( $sql, $spool, $connect, $result, $operation );
    $operation = @_[0];
    if( $ghParams{'DBTYPE'} eq "ORACLE" ){
	if( $operation eq 'SPACE' ){
	    $sql = 'select distinct instance_name, version, (select sum(bytes)/1024 from dba_data_files) dbsize, (select sum (bytes)/1024 from v$log) logsize, banner edition, (select sum(bytes)/1024000 from dba_free_space) freespace, s.bytes/1024000 leastfree from v$instance i, v$version v, (select tablespace_name, bytes from dba_free_space order by bytes ) s where v.banner like \'%Oracle%\' and rownum = 1;';
	}
	if( $operation eq 'CURRENTUSERS' ){
	    $sql = 'select username, terminal from v$session group by username, terminal;';
	}

	$connect = "$ghParams{'DBUSER'}/$ghParams{'DBPASS'}\@$ghParams{'DBNAME'}";
	$spool = "test_output.log";
	$result = Exec_ORACLE($sql, $spool, $connect);
    }elsif( $ghParams{'DBTYPE'} eq "MSSQL" ){
	$result = Exec_MSSQL($sql);
    }elsif( $ghParams{'DBTYPE'} eq "DB2" ){
	$result = Exec_DB2($sql);
    }elsif( $ghParams{'DBTYPE'} eq "MYSQL" ){
	$result = Exec_MYSQL($sql);
    }else{ 
	FailOut("Unable to determine how to handle $ghParams{'DBTYPE'}" );
    }
}
#
# End of Run_SQL
###############################################################################




###############################################################################
#  Execute SQL via the Oracle interface
#
sub Exec_ORACLE{
    # Open a connection to oracle and run the query.
    # Wants query, spool, and connect string

    my $query = @_[0];
    my $spool = @_[1];
    my $connect_string = @_[2];
    printf( "Connection string will be: $connect_string\n" );
    printf( "Spooling to: $spool\n" );
    printf( "Query: $query\n" );

    open( DB, "| sqlplus -s  $connect_string" ) or 
        exit( "Can't pipe to sqlplus: $!" );
    print DB "set trimspool off pagesize 1000 linesize 200 head off feedback off colsep ',' \n";
    print DB "spool $spool append \n";
    #print DB "set timing on \n";
    print DB "$query \n";
    #print DB "select sysdate from dual;";
    print DB "spool off \n";
    print DB "exit \n";
    close DB;
}
#
# End of Exec_ORACLE
###############################################################################

###############################################################################
#  Execute SQL via the MSSQL interface
#
sub Exec_MSSQL{
    printf( "Sorry, the MSSQL execution feature is still incomplete\n" );
}
#
# End of Exec_MSSQL
###############################################################################

###############################################################################
#  Execute SQL via the DB2 interface
#
sub Exec_DB2{
    printf( "Sorry, the DB2 execution feature is still incomplete\n" );
}
#
# End of Exec_DB2
###############################################################################

###############################################################################
#  Execute SQL via the MySQL interface
#
sub Exec_MYSQL{
    printf( "Sorry, the MySQL execution feature is still incomplete\n" );
}
#
# End of Exec_MYSQL
###############################################################################


###############################################################################
#  Write JSON formatted data from a hash
#
sub Write_JSON{
    my %Output;
    foreach( keys %Output ){
	printf( "$_ $Output{$_}{'LABEL'}\n" );
    }
}
#
# End of Write_JSON
###############################################################################

#
# End of Subroutines
###############################################################################
