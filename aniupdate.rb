#!/usr/local/bin/ruby -w
#
#-----------------------------------------------------------------------------
#
# Copyright (c) 2006
#	by Dirk Meyer, All rights reserved.
#	Im Grund 4, 34317 Habichtswald, Germany
#	Email: dirk.meyer@dinoex.sub.org
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the author nor the names of any co-contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#-----------------------------------------------------------------------------
#
#	aniupdate - udp client for http://anidb.net/
#	============================================
#
#	$Id$
#
#-----------------------------------------------------------------------------


#-----------------------------------------------------------------------------

class My_Config_Entry
	attr_accessor :val
	attr_reader :name

	def initialize( name, default )
		@name = name
		@val = default
	end
end

class My_Config
	attr_reader :list

	def initialize( hash )
		@list = Hash.new
		hash.each_pair { |key, value|
			@list[ key ] = My_Config_Entry.new( key, value )
		}
	end

	def [] name
		if @list[ name ].nil?
			STDERR.print "Config: Variable #{name} unbekannt!\n"
		else
			return @list[ name ].val
		end
	end

	def find( name )
		@list[ name ]
	end

	def []= name, val
		if @list[ name ].nil?
			STDERR.print "Config: Variable #{name} unbekannt!\n"
		else
			@list[ name ].val = val
		end
	end

	def parse_line( data )
		if data[ 0 .. 0 ] == '#'
			return
		end

		# Syntax key = val
		key, text = data.split( '=', 2 )
		if text.nil?
			STDERR.print "Config: Variable Ausdruck #{data} unbekannt!\n"
			return
		end
		key.strip!
		text.strip!
		if text[ 0 .. 0 ] == '"'
			text = text[1 .. -1].chomp( '"' )
		else
			text = text.to_i
		end
		self[ key ] = text
	end

	def read( filename )
		File.open( filename ).each { |line|
			parse_line( line )
		}
	end
end


#-----------------------------------------------------------------------------

require 'bdb1'

$local_db_option = { "set_pagesize" => 1024, "set_cachesize" => 32 * 1024 }

def silently(&block)
	warn_level = $VERBOSE
	$VERBOSE = nil
	result = block.call
	$VERBOSE = warn_level
	result
end

class Local_db
#	attr_accessor :filename

	def initialize( name )
		@filename = name
	end

	def cleanup( valid_after )
		begin
			db = BDB1::Hash.open( @filename, BDB1::WRITE, 0600, $local_db_option )
#			db.flock(File::LOCK_EX)
			db.each do |k, v|
				saved_text, data = v.split( '|', 2 )
				saved = Time.at( saved_text.to_i )
				if saved < valid_after
					db.del( k )
					db.sync
				end
			end
#			db.flock(File::LOCK_UN)
			db.close
		rescue
			STDERR.print "Database: #{@filename} nicht gefunden!\n"
			raise
			exit EX_NOINPUT
		end
	end

	def delete( key )
		begin
			db = BDB1::Hash.open( @filename, BDB1::WRITE | BDB1::CREATE, 0600, $local_db_option )
#			db.flock(File::LOCK_EX)
			silently do
				db.db_del( key )
			end
#			db.flock(File::LOCK_UN)
			db.close
		rescue
			STDERR.print "Database: #{@filename} nicht gefunden!\n"
			raise
			exit EX_NOINPUT
		end
	end

	def write_raw( key, value )
		begin
			db = BDB1::Hash.open( @filename, BDB1::WRITE | BDB1::CREATE, 0600, $local_db_option )
#			db.flock(File::LOCK_EX)
			db[ key ] = value
			db.sync
#			db.flock(File::LOCK_UN)
			db.close
			return value
		rescue
			STDERR.print "Database: #{@filename} nicht gefunden!\n"
			raise
			exit EX_NOINPUT
		end
	end

	def write( key, value )
		now = Time.new.to_i
		return write_raw( key, "#{now}|#{value}" )
	end

	def read( key )
		begin
			db = BDB1::Hash.open( "#{@filename}", BDB1::RDONLY, 0600, $local_db_option )
			data = db[ key ]
			db.close
			return data
		rescue
			STDERR.print "Database: #{@filename} nicht gefunden!\n"
			raise
			exit EX_NOINPUT
		end
	end
end


#-----------------------------------------------------------------------------

require 'socket'

class Udp_Api
	SHUT_RDWR = 2

	def initialize
		@connected = false
		@next_send = 0
		@retry_count = 0
		@batch_count = 0
	end

	def save
		if @next_send > Time.new
			$session_db.delete( 'next_send' )
		else
			$session_db.write( 'next_send', @next_send.to_i )
		end
	end

	def delay( seconds )
		@next_send += seconds
		save
	end

	def close
		if not @connected
			return
		end
		@s.shutdown( SHUT_RDWR )
		@connected = false
		save
	end

	def open
		@s = UDPSocket.new
		@s.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1 )
		@s.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1 )
		@s.bind( '0.0.0.0', $config[ 'Local_port' ] )
		@s.connect( $config[ 'Server_name' ], $config[ 'Remote_port' ] )
		@connected = true
		@next_send = Time.new
		data = $session_db.read( 'next_send' )
		if not data.nil?
			saved, text = data.split( '|', 2 )
			if not text.nil?
				saved_next = Time.at( text.to_i )
				if saved_next > @next_send
					@next_send = saved_next
				end
			end
		end
	end

	def send_retry
		if @retry_buf.nil?
			STDERR.print "UDP: retry Daten verloren!\n"
			return
		end
		delay = @next_send - Time.new
		if delay > 0
			Kernel.sleep( delay )
		end
		if $config[ 'Debug' ] != 0
			STDOUT.print "#{@retry_buf}\n"
		end
		@s.send( "#{@retry_buf}", 0 )
		@batch_count += 1
		if $config[ 'Batch_mode' ] != 0 or @batch_count > 50
			@next_send += 31
		else
			@next_send += 3
		end
	end

	def send( buffer )
		if not @connected 
			open
		end
		@retry_count = $config[ 'Retrys' ]
		@retry_buf = buffer
		send_retry
	end

	def recv
		if not @connected 
			open
		end
		begin
			Kernel::select( [ @s ], nil, nil, $config[ 'Timeout' ] )
			data = @s.recvfrom( $max_entry )
			if data.nil?
				#  (errno == ECONNREFUSED)
				if data.nil?
					@next_send = Time.new
					@next_send += 30 * 60
					save
					STDERR.print "UDP: Verbindung abgewiesen!\n"
					STDERR.print "recv #{data}\n"
					exit EX_TEMPFAIL
				end
				#  (errno == EAGAIN)
				if @retry_count == 0 and data.nil?
					STDERR.print "UDP: Verbindung fehlgeschlagen!\n"
					STDERR.print "recv #{data}\n"
					exit EX_OSERR
				end
				STDERR.print "recv #{data}\n"
				@retry_count -= 1
				send_retry
				return recv
			end
			# llen == 0
			if data.nil?
				@retry_count -= 1
				send_retry
				return recv
			end
			if $config[ 'Debug' ] != 0
				STDOUT.print "#{data[0]}\n"
			end
			return data[0]
#		rescue
#			@retry_count -= 1
#			send_retry
#			retry
		end
	end
end


#-----------------------------------------------------------------------------

class File_Key
	attr_reader :hash_key
	attr_reader :hash_size
	attr_reader :hash_md4
	attr_reader :hash_link
	attr_reader :hash_dbkey
	attr_reader :hash_anidbkey

	def initialize
		@hash_key = nil
		@hash_size = nil
		@hash_md4 = nil
		@hash_link = nil
		@hash_dbkey = nil
		@hash_anidbkey = nil
	end

	# in
	# ed2k://|file|[PM]Princess_Tutu_13[A0BC1BC8].avi|146810880|0436df97e7fe25b620edb25380717479|
	# out:
	# 146810880
	# 0436df97e7fe25b620edb25380717479
	def may_ed2klink( link )
		link.scan( /ed2k[:][^|]*[|][^|]*[|][^|]*[|]([^|]*)[|]([^|]*)[|]/ )  do |entry|
			if entry[0].nil? or entry[1].nil?
				return false
			end
			@hash_size = entry[0]
			@hash_md4 = entry[1].downcase
			@hash_link = link
			@hash_dbkey = "#{$hash.hash_size}|#{$hash.hash_md4}"
			@hash_anidbkey = "size=#{$hash.hash_size}&ed2k=#{$hash.hash_md4}"
			return true
		end
		return false
	end

	def must_ed2klink( key, try )
		ok = may_ed2klink( key )
		if not ok and not try.nil?
			STDERR.print "File not an ed2k link: #{try}\n"
		end
	end

	def generate_hash( filename )
		cmdline = $config[ 'Hash_program' ]
		cmdline << " '"
		cmdline << filename
		cmdline << "'"
		begin
			return IO.popen( cmdline ).gets
		rescue
			STDERR.print "cannot execute hash from program: #{cmdline}\n"
			return nil
		end
	end

	def filename_to_hash( key )
		# cached value
		if key == @hash_key
			return
		end
		# new value
		@hash_key = key
		@hash_size = nil
		@hash_md4 = nil
		@hash_link = nil

		if may_ed2klink( key )
			return
		end

		base = key.sub( /^.*\//, '' )
		data = $names_db.read( base )
                if not data.nil?
			must_ed2klink( data, base )
			return
                end
		data = generate_hash( key )
                if data.nil?
			return 
		end
		db.write( base, data )
		must_ed2klink( data, basee )
	end
end


#-----------------------------------------------------------------------------

class Anidb_Api

	def initialize
		@tag = '##nosession##'
		@auth_delay = 0
		@server_status = ""
		@session = nil
	end

	def status
		@mbuf = @rbuf.sub( /#{@tag} /, '' )
		@server_status = @mbuf[ 0 .. 2 ]
	end

	def nosession
		if @session.nil?
			return
		end
		$session_db.delete( 'session' )
		@session = nil
	end

	def logout
		if @session.nil?
			return
		end
		@sbuf = "LOGOUT s=#{@session}&tag=#{@tag}\n"
		nosession
		$network.send( @sbuf )
		@rbuf = $network.recv
		status
		if @server_status == "203" or @server_status == "403"
			return
		end

		# try to close all sessions
		@sbuf = "LOGOUT\n"
		@server_status = status
		$network.send( @sbuf )
		@rbuf = $network.recv
		status
	end

	def delay_login
		@auth_delay ++
		case @auth_delay
		when 1
			$network.delay( 30 )
		when 2
			$network.delay( 2 * 60 )
		when 3
			$network.delay( 5 * 60 )
		when 4
			$network.delay( 10 * 60 )
		else
			add = 30 * 60
			add << ( @auth_delay - 4 )
			$network.delay( add )
		end
	end

	def login
		if @session.nil?
			nosession
		end
		@tag = $config[ 'User' ]

		data = $session_db.read( 'session' )
		if not data.nil?
			saved, text = data.split( '|', 2 )
			if not text.nil?
				saved_time = Time.at( saved.to_i )
				valid_time = Time.new - (24 * 60 * 60)
				if saved_time > valid_time
					@session = text
					return
				end
			end
		end

		@sbuf = "AUTH user=#{$config[ 'User' ]}&pass=#{$config[ 'Password' ]}&protover=3&client=aniupdate&clientver=2&tag=#{@tag}\n"
		$network.send( @sbuf )
		@rbuf = $network.recv
		status
		case @server_status
		when "200", "201"
			STDERR.print "Server returns: #{@rbuf}\n"
		when "503", "504", "505"
			delay_login
			STDERR.print "Server returns: #{@rbuf}\n"
		when "500", "501", "502", "506"
			delay_login
			STDERR.print "Server returns: #{@rbuf}\n"
			exit EX_NOUSER
		when "507", "555", "601", "666"
			$network.delay( 30 * 60 )
			STDERR.print "Server returns: #{@rbuf}\n"
			exit EX_TEMPFAIL
		else
			STDERR.print "Server returns: #{@rbuf}\n"
			exit EX_TEMPFAIL
		end

		saved, text, rest = @mbuf.split( ' ', 3 )
		if text.nil?
			STDERR.print "Server returns: #{@rbuf}\n"
			exit EX_TEMPFAIL
		end
		@session = text
		@auth_delay = 0
		$session_db.write( 'session', @session )
	end

	def ping
		@sbuf = "PING tag=#{@tag}\n"
		$network.send( @sbuf )
		@rbuf = $network.recv
		status
		if @server_status != "300"
			STDERR.print "Server returns: #{@rbuf}\n"
		end
	end

	def fetch( db, cmd, key, force )
		if $config[ 'Cache_ignore' ] == 0 and force == 0 and not db.nil?
			data = db.read( key )
			if not data.nil?
				return data
			end
		end

		if @session.nil?
			login
		end
		if @session.nil?
			return nil
		end

		@sbuf = "#{cmd}&s=#{@session}&tag=#{@tag}\n"
		$network.send( @sbuf )
		@rbuf = $network.recv
		status
		case @server_status
		when "210", "220", "221", "230", "240", "250"
			# update vaild session
			$session_db.write( 'session', @session )
		when "501", "506"
			nosession
			return fetch( db, cmd, key, force )
		when "310", "311", "320", "321", "330", "340", "350"
			STDERR.print "Server returns: #{@rbuf}\n"
			return nil
		when "507", "555", "601", "666"
			$network.delay( 30 * 60 )
			STDERR.print "Server returns: #{@rbuf}\n"
			exit EX_TEMPFAIL
		when "500", "501", "502", "506"
			delay_login
			STDERR.print "Server returns: #{@rbuf}\n"
			exit EX_NOUSER
		else
			STDERR.print "Server returns: #{@rbuf}\n"
			return nil
		end
			
		if db.nil?
			return @rbuf
		end
		status, text, rest = @mbuf.split( "\n", 3 )
		if text.nil?
			STDERR.print "Server returns: #{@rbuf}\n"
			return nil
		end
		return db.write( key, text )
	end

	def animes( key, force )
		if $config[ 'Verbose' ] != 0
			STDOUT.print "animes: #{key}\n"
		end
		@cbuf = "ANIME aid=#{key}"
		return fetch( $animes_db, @cbuf, key, force )
	end

	def episodes( key, force )
		if $config[ 'Verbose' ] != 0
			STDOUT.print "episodes: #{key}\n"
		end
		@cbuf = "EPISODE eid=#{key}"
		return fetch( $episodes_db, @cbuf, key, force )
	end

	def groups( key, force )
		if $config[ 'Verbose' ] != 0
			STDOUT.print "groups: #{key}\n"
		end
		@cbuf = "GROUP gid=#{key}"
		return fetch( $groups_db, @cbuf, key, force )
	end

	def files( key, force )
		if $config[ 'Verbose' ] != 0
			STDOUT.print "files: #{key}\n"
		end
		$hash.filename_to_hash( key )
		if $hash.hash_dbkey.nil?
			return nil
		end
		@cbuf = "FILE #{$hash.hash_anidbkey}"
		return fetch( $files_db, @cbuf, $hash.hash_dbkey, force )
	end

	def mylist( key, force )
		if $config[ 'Verbose' ] != 0
			STDOUT.print "mylist: #{key}\n"
		end
		$hash.filename_to_hash( key )
		if $hash.hash_dbkey.nil?
			return nil
		end
		@cbuf = "MYLIST #{$hash.hash_anidbkey}"
		return fetch( $mylist_db, @cbuf, $hash.hash_dbkey, force )
	end

	def add( key, edit )
		if $config[ 'Verbose' ] != 0
			STDOUT.print "add: #{key}\n"
		end
		$hash.filename_to_hash( key )
		if $hash.hash_dbkey.nil?
			return nil
		end
		@cbuf = "MYLISTADD #{$hash.hash_anidbkey}"
		if edit.nil?
			@cbuf << "&state=#{$config[ 'Add_state' ]}"
			@cbuf << "&viewed=#{$config[ 'Add_viewed' ]}"
			@cbuf << "&source=#{$config[ 'Add_source' ]}"
			@cbuf << "&storage=#{$config[ 'Add_storage' ]}"
			@cbuf << "&other=#{$config[ 'Add_other' ]}"
		else
			@cbuf << "&state=#{edit[ 'state' ]}"
			@cbuf << "&viewed=#{edit[ 'viewdate' ]}"
			@cbuf << "&source=#{edit[ 'source' ]}"
			@cbuf << "&storage=#{edit[ 'storage' ]}"
			@cbuf << "&other=#{edit[ 'other' ]}"
		end
		return fetch( nil, @cbuf, $hash.hash_dbkey, 0 )
	end
end
	

#-----------------------------------------------------------------------------

$response_mylist = [
        "lid",
        "fid",
        "eid",
        "aid",
        "gid",
        "date",
        "state",
        "viewdate",
        "storage",
        "source",
        "other"
]

$response_file = [
        "fid",
        "aid",
        "eid",
        "gid",
        "state",
        "size",
        "ed2k",
        "anidbfilename"
]

$response_anime = [
        "aid",
        "eps_total",
        "eps_normal",
        "eps_special",
        "rating",
        "votes",
        "tmprating",
        "itmpvotes",
        "review_rating",
        "reviews",
        "year",
        "type",
        "romaji",
        "kanji",
        "english",
        "other",
        "short_names",
        "synonyms",
        "category_list"
]

$response_episode = [
        "eid",
        "aid",
        "length",
        "rating",
        "votes",
        "epno",
        "english",
        "romaji",
        "kanji"
]

$response_group = [
        "gid",
        "rating",
        "votes",
        "acount",
        "fcount",
        "name",
        "short",
        "chan",
        "irc",
        "url"
]

$mylist_states = [
        "unknown",
        "on hdd",
        "on cd",
        "deleted",
        "shared",
        "release"
]

$info_crc = [
        "unknown",
        "ok",
        "bad",
        "unknown"
]

def print_date( prefix, seconds )
	if seconds.nil?
		return
	end
	lsec = seconds.to_i
	if lsec == 0
		return
	end
	
	text = Time.at( lsec ).strftime( $config[ 'Date_format' ] )
        printf("%stext: %s\n", prefix, text)
end

def show_anidb( info, key, data )
	files = false
	if info[ 0 ] == "fid"
		files = true
	end
	mylist = false
	if info[ 0 ] == "lid"
		mylist = true
	end
	if files or mylist
		$hash.filename_to_hash( key )
		if not $hash.hash_size.nil?
			printf("%s: %s\n", 'size', $hash.hash_size);
			printf("%s: %s\n", 'ed2khash', $hash.hash_md4);
		end
	end
	linfo = [ 'cached' ] + info
	field = data.split( '|' )
	linfo.each_index { |i|
		printf("%s: %s\n", linfo[i], field[i])
		case linfo[i]
		when "cached"
			print_date( linfo[i], field[i] )
		when /date$/
			print_date( linfo[i], field[i] )
		when "state"
			st = field[i].to_i
			if files
				if not $mylist_states[ st ].nil?
					printf("%s: %s\n", 'statetext', $mylist_states[ st ] )
				end
			end
			if mylist
				crc = st & 0x03
				rver = st & 0x3c
				printf("%s: %s\n", 'crc', $info_crc[ crc ] )
				case rver
				when 0
					version = "1"
				when 1
					version = "2"
				when 2
					version = "3"
				when 4
					version = "4"
				when 8
					version = "5"
				else
					version = "unknown"
				end
				printf("%s: %s\n", 'version', version )
				if ( st & 0x40 ) != 0
					printf("censored: uncut\n")
				end
				if ( st & 80 ) != 0
					printf("censored: censored\n")
				end
			end
		end
	}
	printf("\n")
end

def mylist_decode( key, data )
	$hash.filename_to_hash( key )
	if $hash.hash_size.nil?
		return nil
	end

	linfo = [ 'cached' ] + $response_mylist
	mylist = Hash.new
	field = data.split( '|' )
	linfo.each_index { |i|
		mylist[ linfo[i] ] = field[i]
	}
	return mylist
end

def mylist_edit( mylist, changes )
	if changes.nil?
		return nil
	end

	key, value = changes.split( '=', 2 )
	if value.nil?
		return nil
	end
	case key
	when /^o/
		mylist[ 'other' ] = "#{value}"
	when /^so/
		mylist[ 'source' ] = "#{value}"
	when /^st/
		mylist[ 'storage' ] = "#{value}"
	else
		return nil
	end
	return mylist
end

#-----------------------------------------------------------------------------

EX_USAGE = 64
EX_DATAERR = 65
EX_NOINPUT = 66
EX_NOUSER = 67
EX_NOHOST = 68
EX_UNAVAILABLE = 69
EX_SOFTWARE = 70
EX_OSERR = 71
EX_OSFILE = 72
EX_CANTCREAT = 73
EX_IOERR = 74
EX_TEMPFAIL = 75
EX_NOPERM = 77
EX_CONFIG = 78

def usage
	STDERR.print( '

 Usage: aniupdate [options] [...] commands [...]

 options:
-debug            show datagramms
-verbose          show files processed
-quiet            dont print data
-f <config>       set name of config file, default .aniudate
--<name>=<value>  overrite config with given value
-local <port>     set local port number, default 9000
-remote <port>    set remote port number, default 9000
-server <name>    set remote host, default anidb.ath.cx
-user             set userid

 commands:
+ping                    test communication
+mylist ed2klink [...]   add files to mylist
+read ed2klink [...]     read mylist info
+view ed2klink [...]     set files as viewed (date will not be preserved)
+unview ed2klink [...]   set files as unviewed
+write key=value ed2klink [...]   change a field in mylist
+anime id [...]          read anime info
+episode id [...]        read episode info
+group id [...]          read group info
+file ed2klink [...]     read file info

' )
        exit EX_USAGE
end

def command_config( argv )
	largv = Array.new
	largv += argv
	loop do
		arg = largv.shift
		if arg.nil?
			return
		end
		if arg[ 0 .. 0 ] == "-"
			case arg[ 1 .. 1 ].downcase
			when "d"
				$config[ 'Debug' ] = 1
			when "f"
				$config[ 'Config_file' ] = largv.shift
			when "q"
				$config[ 'Quiet' ] = 1
			when "v"
				$config[ 'Verbose' ] = 1
			end
		end
	end
end

def command_options( argv )
	fc = ""
	largv = Array.new
	largv += argv
	loop do
		arg = largv.shift
		if arg.nil?
			return
		end
		if arg[ 0 .. 0 ] == "-"
			case arg[ 1 .. 1 ].downcase
			when "-"
				$config.parse_line( arg[ 2 .. -1 ] )
			when "d"
				$config[ 'Debug' ] = 1
			when "f"
			when "l"
				$config[ 'Local_port' ] = largv.shift
			when "p"
				$config[ 'Password' ] = largv.shift
			when "q"
				$config[ 'Quiet' ] = 1
			when "r"
				$config[ 'Remote_port' ] = largv.shift
			when "s"
				$config[ 'Server_name' ] = largv.shift
			when "u"
				$config[ 'User' ] = largv.shift
			when "v"
				$config[ 'Verbose' ] = 1
			else
				usage
			end
			next
		end
		# sntax check
		if arg[ 0 .. 0 ] == "+"
			fc = arg[ 1 .. 1 ].downcase
			case fc
			when "a", "e", "f", "g", "m", 'p', "r", "u", "v"
			when "w"
				largv.shift
			else
				usage
			end
			next
		end
		case fc
		when "a", "e", "f", "g", "m", "r", "u", "v", 'w'
		else
			usage
		end
	end
end

def command_run( argv )
	write = nil
	fc = ""
	largv = Array.new
	largv += argv
	loop do
		arg = largv.shift
		if arg.nil?
			return
		end
		if arg[ 0 .. 0 ] == "-"
			next
		end
		if arg[ 0 .. 0 ] == "+"
			fc = arg[ 1 .. 1 ].downcase
			case fc
			when 'p'
				$anidb.ping
			when "w"
				write = largv.shift
			end
			next
		end
		case fc
		when "a"
			data = $anidb.animes( arg, 0 )
			if ( data.nil? ) or ( $config[ 'Quiet' ] != 0 )
				next
			end
			show_anidb($response_anime, arg, data)
		when "e"
			data = $anidb.episodes( arg, 0 )
			if ( data.nil? ) or ( $config[ 'Quiet' ] != 0 )
				next
			end
			show_anidb($response_episode, arg, data)
		when "f"
			data = $anidb.files( arg, 0 )
			if ( data.nil? ) or ( $config[ 'Quiet' ] != 0 )
				next
			end
			show_anidb($response_file, arg, data)
		when "g"
			data = $anidb.groups( arg, 0 )
			if ( data.nil? ) or ( $config[ 'Quiet' ] != 0 )
				next
			end
			show_anidb($response_group, arg, data)
		when "m"
			$anidb.add( arg, nil )
		when "r"
			data = $anidb.mylist( arg, 0 )
			if ( data.nil? ) or ( $config[ 'Quiet' ] != 0 )
				next
			end
			show_anidb($response_mylist, arg, data)
		when "u"
			data = $anidb.mylist( arg, 0 )
			if ( data.nil? )
				next
			end
			mylist_entry = mylist_decode(arg, data)
			mylist_entry[ 'viewdate' ] = "0"
			$anidb.add( arg, mylist_entry )
			data = $anidb.mylist( arg, 1 )
		when "v"
			data = $anidb.mylist( arg, 0 )
			if ( data.nil? )
				next
			end
			mylist_entry = mylist_decode(arg, data)
			if mylist_entry[ 'viewdate' ] != "0"
				next
			end
			mylist_entry[ 'viewdate' ] = "1"
			$anidb.add( arg, mylist_entry )
			data = $anidb.mylist( arg, 1 )
		when "w"
			data = $anidb.mylist( arg, 0 )
			if ( data.nil? )
				next
			end
			mylist_entry = mylist_decode(arg, data)
			mylist_entry = mylist_edit( mylist_entry, write )
			if mylist_entry.nil?
				usage
			end
			$anidb.add( arg, mylist_entry )
			data = $anidb.mylist( arg, 1 )
		end
	end
end


#-----------------------------------------------------------------------------

$max_entry = 1024

$config = My_Config.new( {
	# Config
	"Config_file" => ".aniupdate",

	# Databases
	"Animes_db" => "animes.db",
	"Episodes_db" => "episodes.db",
	"Groups_db" => "groups.db",
	"Files_db" => "files.db",
	"Mylist_db" => "mylist.db",
	"Names_db" => "names.db",
	"Session_db" => ".session.db",

	# Account
	"Server_name" => "localhost",
	"Remote_port" => 9000,
	"Local_port" => 9000,
	"User" => nil,
	"Password" => nil,

	# Network
	"Keep_session" => 0,
	"Retrys" => 2,
	"Timeout" => 30,

	# Options
	"Debug" => 0,
	"Verbose" => 0,
	"Quiet" => 0,
	"Batch_mode" => 0,
	"Cache_ignore" => 0,

	# External Data and Tools
	"Date_format" => "%Y-%m-%d %H:%M:%S",
	"Hash_program" => "edonkey-hash",

	# Default mylist
	"Add_other" => "",
	"Add_source" => "",
	"Add_storage" => "",
	"Add_state" => 1,
	"Add_viewed" => nil
} )

begin
	command_config( ARGV )
rescue
	usage
end
$config.read $config[ 'Config_file' ]
begin
	command_options( ARGV )
rescue
	usage
end
if $config[ 'User' ].nil?
	STDERR.print "User not set\n"
	exit EX_CONFIG
end
if $config[ 'Password' ].nil?
	STDERR.print "Password not set\n"
	exit EX_CONFIG
end
$session_db = Local_db.new( $config[ 'Session_db' ] )
$network = Udp_Api.new
$anidb = Anidb_Api.new
$animes_db = Local_db.new( $config[ 'Animes_db' ] )
$episodes_db = Local_db.new( $config[ 'Episodes_db' ] )
$groups_db = Local_db.new( $config[ 'Groups_db' ] )
$files_db = Local_db.new( $config[ 'Files_db' ] )
$mylist_db = Local_db.new( $config[ 'Mylist_db' ] )

$names_db = Local_db.new( $config[ 'Names_db' ] )
$hash = File_Key.new

command_run( ARGV )

if $config[ 'Keep_session' ] == 0
	$anidb.logout
end
$network.close
exit 0

# EOF
