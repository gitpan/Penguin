#!/usr/bin/perl

use Penguin;
use PGP;

PGP::setpassword("ants in my pants");
print("sending code...\n");
$y = Penguin::sendcode("print hello", "localhost", 5059);
print("..sent.\n");
