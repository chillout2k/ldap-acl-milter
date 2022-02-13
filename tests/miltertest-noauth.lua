-- https://mopano.github.io/sendmail-filter-api/constant-values.html#com.sendmail.milter.MilterConstants
-- http://www.opendkim.org/miltertest.8.html

-- socket must be defined as miltertest global variable (-D)
conn = mt.connect(socket)
if conn == nil then
  error "mt.connect() failed"
end
if mt.conninfo(conn, "blubb-ip.host", "127.255.255.254") ~= nil then
  error "mt.conninfo() failed"
end

mt.set_timeout(60)

-- 5321.FROM
if mt.mailfrom(conn, "tester-noauth@test.blah") ~= nil then
  error "mt.mailfrom() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.mailfrom() unexpected reply"
end

-- 5321.RCPT+MACROS
mt.macro(conn, SMFIC_RCPT, "i", "4CgSNs5Q9sz7SllQ")
if mt.rcptto(conn, "<rcpt-noauth@test.blubb>") ~= nil then
-- if mt.rcptto(conn, "<rcpt-noauth@>") ~= nil then
  error "mt.rcptto() failed"
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
  error "mt.rcptto() unexpected reply"
end

-- 5322.HEADERS
if mt.header(conn, "fRoM", '"Blah Blubb" <tester-noauth@test.blah>') ~= nil then
  error "mt.header(From) failed"  
end
if mt.header(conn, "Authentication-REsuLTS", "my-auth-serv-id;\n  dkim=pass header.d=test.blah header.s=selector1-test-blah header.b=mumble") ~= nil then
  error "mt.header(Authentication-Results) failed"  
end

-- EOM
if mt.eom(conn) ~= nil then
  error "mt.eom() failed"
end
mt.echo("EOM: " .. mt.getreply(conn))
if mt.getreply(conn) == SMFIR_CONTINUE then
  mt.echo("EOM-continue")
elseif mt.getreply(conn) == SMFIR_REPLYCODE then
  mt.echo("EOM-reject")
end

-- DISCONNECT
mt.disconnect(conn)