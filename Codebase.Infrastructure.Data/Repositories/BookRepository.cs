using System;
using Codebase.Domain.Interfaces;
using Codebase.Domain.Models;
using Codebase.Infrastructure.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace Codebase.Infrastructure.Data.Repositories;

public class BookRepository : IBookRepository
{
    public ApplicationDBContext _context;
    public BookRepository(ApplicationDBContext context)
    {
        _context = context;
    }

    public Book CreateBook(Book data)
    {
        _context.Books.Add(data);
        _context.SaveChanges();
        
        return data;
    }

    public bool DeleteBook(int ID)
    {
        var data = _context.Books.FirstOrDefault(row => row.ID == ID);
        _context.Books.Remove(data);
        _context.SaveChanges();

        return true;
    }

    public Book GetBook(int ID)
    {
        return _context.Books.FirstOrDefault(row => row.ID == ID);
    }

    public IEnumerable<Book> GetBooks()
    {
        return _context.Books;
    }

    public bool IsExist(string Title)
    {
        var data = _context.Books.FirstOrDefault(row => row.Title == Title);
        if(data == null)
            return false;

        return true;
    }

    public Book UpdateBook(Book data)
    {
        _context.Books.Update(data);
        _context.SaveChanges();
        
        return data;
    }
}
