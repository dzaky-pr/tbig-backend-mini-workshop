using System;
using Codebase.Application.Interfaces;

namespace Codebase.API.Features.Book.DeleteBook;

public class Endpoint: Endpoint<Request, Response>
{
    private IBookService _bookService;
    public Endpoint(IBookService bookService)
    {
        _bookService = bookService;
    }

    public override void Configure()
    {
        Delete("book/delete");
    }

    public override async Task HandleAsync(Request req, CancellationToken ct)
    {
        _bookService.DeleteBook(req.ID);
        
        Response.IsSuccess = true;
        Response.Message = "";
        
        await SendAsync(Response);
    }
}