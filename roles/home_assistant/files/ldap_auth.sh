#!/bin/sh

# An empty password is an anonymous bind, which AD accepts. Refuse it.
[ -n "$username" ] && [ -n "$password" ] || exit 1

user=${username#*\\}
case $user in
  *@*) upn=$user ;;
  *)   upn=$user@ice.land ;;
esac

result=$(printf '%s' "$password" | ldapsearch -LLL -x -o nettimeout=5 -o ldif_wrap=no \
  -H ldap://192.168.220.79 -D "$upn" -y /dev/stdin \
  -b DC=ice,DC=land "(userPrincipalName=$upn)" displayName memberOf) || exit 1

name=$(printf '%s\n' "$result" | sed -n 's/^displayName: //p')
echo "name = ${name:-$user}"

if printf '%s\n' "$result" | grep -qix 'memberOf: CN=Domain Admins,CN=Users,DC=ice,DC=land'; then
  echo "group = system-admin"
else
  echo "group = system-users"
fi
