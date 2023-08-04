/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Package: PkiAuthenticator
* File: ProcessArguments.cs 
*
* PkiAuthenticator is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* PkiAuthenticator is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with PkiAuthenticator. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.Linq;
using System.Collections.Generic;

namespace PkiAuthenticator
{
    internal class ProcessArguments
    {
        private readonly List<string> _args;

        public ProcessArguments(string[] args) => _args = args.ToList();

        public bool HasArg(string arg) => _args.Contains(arg, StringComparer.OrdinalIgnoreCase);

        public bool Verbose => HasArg("-v") || HasArg("--verbose");
        public bool Debug => HasArg("-d") || HasArg("--debug");
        public bool Silent => HasArg("-s") || HasArg("--silent");
        public bool DoubleVerbose => Verbose && HasArg("-vv");

        public bool LogHttp => HasArg("--log-http");

        /// <summary>
        /// Gets the value following the specified argument, or 
        /// null no value follows the specified argument
        /// </summary>
        /// <param name="arg"></param>
        /// <returns></returns>
        public string? GetArg(string arg)
        {
            int index = _args.IndexOf(arg);
            return index == -1 || index + 1 >= _args.Count ? null : _args[index + 1];
        }
    }
}
