#!/usr/bin/perl

use Safe;
use Penguin;
use PGP;

PGP::setpassword("The Quatrain in Spain is Truly Slain");
Penguin::startlistening;

print("getting code for the next 30 seconds...\n");
($username, $code) = Penguin::getcodeifthere(30);

print("username was $username\n");
print("code is:\n$code\n");
