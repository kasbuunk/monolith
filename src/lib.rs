use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: mpsc::Sender<Message>,
}

trait FnBox {
    fn call_box(self: Box<Self>);
}

impl<F: FnOnce()> FnBox for F {
    fn call_box(self: Box<F>) {
        (*self)()
    }
}

type Job = Box<dyn FnBox + Send + 'static>;

enum Message {
    NewJob(Job),
    Terminate,
}

impl ThreadPool {
    /// Create a new ThreadPool.
    ///
    /// The size is the number of threads in the pool.
    ///
    /// # Panics
    ///
    /// The `new` function will panic if the size is zero.
    pub fn new(size: usize) -> ThreadPool {
        assert!(size > 0);

        let (sender, receiver) = mpsc::channel();

        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }
        ThreadPool { workers, sender }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.send(Message::NewJob(job)).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        println!("Sending terminate message to all workers.");

        for _ in &mut self.workers {
            self.sender.send(Message::Terminate).unwrap();
        }

        println!("Shutting down all workers.");

        for worker in &mut self.workers {
            println!("Shutting down worker {}.", worker.id);
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv().unwrap();

            match message {
                Message::NewJob(job) => {
                    println!("Worker {} got a job; executing.", id);

                    job.call_box();
                }
                Message::Terminate => {
                    println!("Worker {} was told to terminate", id);

                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}

pub struct TCPListener {
    thread_pool: ThreadPool,
    app: App,
}

impl TCPListener {
    pub fn new(num_workers: usize, app: App) -> TCPListener {
        let thread_pool = ThreadPool::new(num_workers);

        TCPListener { thread_pool, app }
    }

    // listen initialises a worker pool of tcp listeners.
    // Usage: telnet 127.0.0.1:{port}
    // or: nc 127.0.0.1:{port} < input_file
    pub fn listen(&self, port: u16) {
        let address = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(address).unwrap();

        for stream in listener.incoming() {
            let stream = stream.unwrap();

            let app_clone = self.app.clone();

            self.thread_pool.execute(|| {
                handle_tcp_connection(stream, app_clone);
            });
        }
    }
}

fn handle_tcp_connection(mut stream: TcpStream, app: App) {
    let mut read_buffer = Vec::new();

    match stream.read_to_end(&mut read_buffer) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error reading stream: {}", e);
            return;
        }
    };

    let buffer_str = match std::str::from_utf8(&read_buffer) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Error converting buffer to string: {}", err);
            return;
        }
    };

    let result = parse_request(buffer_str);
    match result {
        Ok(Request::Register(email, password)) => app.register(email, password),
        Ok(Request::LogIn(email, password)) => app.log_in(email, password),
        Err(_) => {
            eprintln!("parsing request");
            return;
        }
    };

    let _response = if let Err(err) = stream.write("User signed up".as_bytes()) {
        eprintln!("Error writing response: {}", err);
    };

    if let Err(err) = stream.flush() {
        eprintln!("Error flushing stream: {}", err);
    };
}

enum Request {
    Register(String, String),
    LogIn(String, String),
}
enum ParseError {
    GenericError,
}

fn parse_request(message: &str) -> Result<Request, ParseError> {
    let mut msg = message.split_whitespace();
    match msg.next() {
        Some("Register") => match (msg.next(), msg.next(), msg.next()) {
            (Some(email), Some(password), None) => Ok(Request::Register(
                String::from(email),
                String::from(password),
            )),
            _ => Err(ParseError::GenericError),
        },
        Some("LogIn") => match (msg.next(), msg.next(), msg.next()) {
            (Some(email), Some(password), None) => {
                Ok(Request::LogIn(String::from(email), String::from(password)))
            }
            _ => Err(ParseError::GenericError),
        },
        _ => Err(ParseError::GenericError),
    }
}

#[derive(Debug)]
struct User {
    email: String,
    password: String,
}

impl User {
    fn new(email: String, password: String) -> User {
        User { email, password }
    }
}

#[derive(Clone)]
pub enum RepositoryMethod {
    InMemory,
    FileSystem,
    Postgres(String),
}

#[derive(Clone)]
pub struct Repository {
    method: RepositoryMethod,
}

impl Repository {
    pub fn new(method: RepositoryMethod) -> Repository {
        Repository { method }
    }

    fn user_get(&self, email: String) -> User {
        match self.method {
            RepositoryMethod::InMemory => {
                // Pretend to retrieve from database.
                let user_from_db = User {
                    email,
                    password: String::from("password"),
                };

                println!("user retrieved: {:?}", user_from_db);

                user_from_db
            }
            _ => User {
                email: String::from("refactor to error"),
                password: String::from(""),
            },
        }
    }

    fn user_create(&self, user: User) -> User {
        let created_user = User {
            email: user.email,
            password: user.password,
        };

        println!("user created: {:?}", created_user);

        created_user
    }
}

#[derive(Clone)]
pub struct App {
    repository: Repository,
}

impl App {
    pub fn new(repository: Repository) -> App {
        App { repository }
    }

    fn register(&self, email: String, password: String) {
        let user = User::new(email, password);
        let _saved_user = self.repository.user_create(user);
    }

    fn log_in(&self, email: String, password: String) {
        let user = self.repository.user_get(email);
    }
}
