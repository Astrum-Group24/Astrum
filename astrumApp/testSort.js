const express = require("express");
const path = require("path");
const shell = require("shelljs");
const fs = require("fs");


var rootPath = '/home/astrum/Main/astrumApp/reports';

var directoryEntries = fs.readdirSync(rootPath)

var subfolders = directoryEntries.filter(isFolder)


shell.echo(directoryEntries);

isfolder(value) 