﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Lab_11.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet("get")]
        // === Oznaczenie koncowki jako takiej, ktora wymaga podania tokenu (bycia "zalogowanym")
        [Authorize]
        public IActionResult Get()
        {
            return Ok();
        }

        [HttpGet("exception")]
        public IActionResult ThrowException()
        {
            throw new Exception("No tragedia :(");
            return Ok();
        }
    }
}
