using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TodoApp.Configuration
{
	public class AuthResult
	{
		public string Token { get; set; }

		public string RefreshToken { get; set; }

		public bool Sucess { get; set; }

		public List<string> Errors { get; set; }
	}
}
