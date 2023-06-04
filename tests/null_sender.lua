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
if mt.mailfrom(conn, "<>") ~= nil then
  error "mt.mailfrom() failed"
end
if mt.getreply(conn) == SMFIR_CONTINUE then
  mt.echo("FROM-continue - null_sender allowed")
elseif mt.getreply(conn) == SMFIR_REPLYCODE then
  error "FROM-reject - disconnect"
end

-- 5321.RCPT+MACROS
mt.macro(conn, SMFIC_RCPT, "i", "4CgSNs5Q9sz7SllQ")
if mt.rcptto(conn, "<rcpt-null@test.blubb>") ~= nil then
  error "mt.rcptto() failed"
end

-- 5322.HEADERS
if mt.header(conn, "fRoM", '"MAILER DAEMON') ~= nil then
  error "mt.header(From) failed"  
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