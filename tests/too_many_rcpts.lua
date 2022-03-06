-- https://mopano.github.io/sendmail-filter-api/constant-values.html#com.sendmail.milter.MilterConstants
-- http://www.opendkim.org/miltertest.8.html

-- socket must be defined as miltertest global variable (-D)
conn = mt.connect(socket)
if conn == nil then
  error "mt.connect() failed"
end
if mt.conninfo(conn, "blubb-ip.host", "127.128.129.130") ~= nil then
  error "mt.conninfo() failed"
end

mt.set_timeout(60)

-- 5321.FROM
if mt.mailfrom(conn, "tester-sender@test.blah") ~= nil then
  error "mt.mailfrom() failed"
end

-- FIRST 5321.RCPT
if mt.rcptto(conn, "<rcpt1@test.blubb>") ~= nil then
  error "mt.rcptto() failed"
end
if mt.getreply(conn) == SMFIR_CONTINUE then
  mt.echo("RCPT1-continue")
elseif mt.getreply(conn) == SMFIR_REPLYCODE then
  mt.echo("RCPT1-reject")
end

-- SECOND 5321.RCPT
if mt.rcptto(conn, "<rcpt2@test.blubb>") ~= nil then
  error "mt.rcptto() failed"
end
if mt.getreply(conn) == SMFIR_CONTINUE then
  mt.echo("RCPT2-continue")
elseif mt.getreply(conn) == SMFIR_REPLYCODE then
  mt.echo("RCPT2-reject")
end

-- SET RCPT-MACRO
mt.macro(conn, SMFIC_RCPT, "i", "some-queue-id")

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