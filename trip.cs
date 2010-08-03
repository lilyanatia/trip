/*
 * Copyright (c) 2005-2008 robert wilson
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using DigiWar.Security.Cryptography;

class Tripper{
 public static void Main(string[] args){
  bool cflag = false, tparam = false;
  string searchstring = "";
  UInt64 threads = 1;
  foreach(string arg in args){
   if(tparam){
    threads = UInt64.Parse(arg);
    tparam = false;
   } else if(arg == "-c") cflag = true;
   else if(arg == "-t") tparam = true;
   else if(arg.StartsWith("-t")) threads = UInt64.Parse(arg.Substring(2));
   else if(arg.StartsWith("-")){
    Console.WriteLine("Usage: " + Environment.GetCommandLineArgs()[0] +
     " [-c] [-t threads] [regex]");
    return;
   } else searchstring = arg;
  }
  Regex regex = new Regex(searchstring, RegexOptions.Compiled | (cflag ? 0 : RegexOptions.IgnoreCase));
  for(; threads > 1; --threads){
   Thread thread = new Thread(Tripper.TripSearch);
   thread.Start(regex);
  }
  if(threads > 0) Tripper.TripSearch(regex);
 }

 public static void TripSearch(object data){
  char[] tripc = " !#$%()*+-./0123456789:;=?ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~".ToCharArray();
  char[] saltc = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray();
  Random rand = RandomFactory.Create();
  Regex regex = (Regex)data;
  for(;;){
   string cap = String.Concat(
    tripc[rand.Next(tripc.Length - 1)],
    saltc[rand.Next(saltc.Length - 1)],
    saltc[rand.Next(saltc.Length - 1)],
    tripc[rand.Next(tripc.Length - 1)],
    tripc[rand.Next(tripc.Length - 1)],
    tripc[rand.Next(tripc.Length - 1)],
    tripc[rand.Next(tripc.Length - 1)],
    tripc[rand.Next(tripc.Length - 1)]);
   string trip = UnixCrypt.Crypt(cap.Substring(1, 2), cap).Substring(3);
   if(regex.IsMatch(trip)) Console.WriteLine(cap + "  =  " + trip);
  }
 }
}

static class RandomFactory{
 private static Random globalRandom = new Random();
 public static Random Create(){
  Random newRandom;
  lock(globalRandom){
   newRandom = new Random(globalRandom.Next());
  }
  return newRandom;
 }
}
