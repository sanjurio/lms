from app import create_app, db
from app.models import Interest, Course, Lesson, CourseInterest, User
from datetime import datetime

def create_interests(admin_id):
    """Create Erlang-related interest categories if they don't exist"""
    interests = {
        'Erlang Fundamentals': 'Core Erlang programming concepts and syntax',
        'OTP (Open Telecom Platform)': 'Erlang/OTP framework for building fault-tolerant applications',
        'Concurrent Programming': 'Actor model and lightweight process management in Erlang',
        'Distributed Systems': 'Building distributed and fault-tolerant systems with Erlang',
        'Telecom Systems': 'Telecommunications and real-time systems development',
        'Fun': 'Fun activities and video content - THBS users only'
    }

    created_interests = {}

    for name, description in interests.items():
        # Check if interest exists
        existing = Interest.query.filter_by(name=name).first()
        if existing:
            print(f"Interest '{name}' already exists")
            created_interests[name] = existing
        else:
            # Create new interest
            interest = Interest(
                name=name,
                description=description,
                created_by=admin_id
            )
            db.session.add(interest)
            db.session.flush()
            print(f"Created interest: {name}")
            created_interests[name] = interest

    db.session.commit()
    return created_interests

def create_sample_courses():
    try:
        # Find admin user
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            print("No admin user found. Please ensure an admin user exists.")
            return

        print(f"Found admin user: {admin.username}")

        # Create or get interests
        interests = create_interests(admin.id)
        if not interests:
            print("Failed to create interests")
            return

        # Access interest objects
        erlang_fundamentals = interests.get('Erlang Fundamentals')
        otp_interest = interests.get('OTP (Open Telecom Platform)')
        concurrent_interest = interests.get('Concurrent Programming')
        distributed_interest = interests.get('Distributed Systems')
        telecom_interest = interests.get('Telecom Systems')
        fun_interest = interests.get('Fun')

        print(f"Found required interests: Erlang, OTP, Concurrent Programming")

        # Create courses
        courses = [
            {
                'title': 'Introduction to Erlang Programming',
                'description': 'Learn the basics of Erlang programming language. This comprehensive course covers functional programming concepts, pattern matching, and the actor model that makes Erlang perfect for concurrent and fault-tolerant systems.',
                'cover_image_url': 'https://images.unsplash.com/photo-1555949963-aa79dcee981c?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&q=80',
                'interests': [erlang_fundamentals],
                'lessons': [
                    {'title': 'What is Erlang?', 'content': 'Erlang is a functional programming language designed for building fault-tolerant, distributed systems. Originally developed by Ericsson for telecom applications, Erlang excels at handling thousands of concurrent processes with minimal overhead. In this lesson, we explore Erlang\'s history, design principles, and why it\'s perfect for building reliable systems that never stop running.', 'order': 1},
                    {'title': 'Basic Syntax and Data Types', 'content': 'Learn Erlang\'s unique syntax and built-in data types including atoms, numbers, lists, tuples, and binaries. We\'ll cover pattern matching, one of Erlang\'s most powerful features, and how to use it for destructuring data and controlling program flow. Practice with hands-on examples to master the fundamentals.', 'order': 2},
                    {'title': 'Functions and Modules', 'content': 'Discover how to write functions in Erlang and organize code into modules. Learn about function clauses, guards, and recursion patterns. Understand how to export functions, handle different arities, and follow Erlang coding conventions for clean, maintainable code.', 'order': 3}
                ]
            },
            {
                'title': 'OTP Design Principles',
                'description': 'Master the Open Telecom Platform (OTP) framework for building robust, scalable applications. Learn about supervisors, gen_servers, and other OTP behaviors that form the backbone of fault-tolerant Erlang systems.',
                'cover_image_url': 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1365&q=80',
                'interests': [otp_interest],
                'lessons': [
                    {'title': 'Introduction to OTP', 'content': 'OTP (Open Telecom Platform) is a set of libraries and design principles for building fault-tolerant applications in Erlang. Learn about the supervision tree, OTP behaviors, and how they work together to create systems that can recover from failures automatically. Understand the "let it crash" philosophy and how it leads to more reliable software.', 'order': 1},
                    {'title': 'GenServer Behavior', 'content': 'GenServer is the most commonly used OTP behavior for implementing stateful server processes. Learn how to implement callbacks like init/1, handle_call/3, handle_cast/2, and handle_info/2. Build a practical example of a stateful server and understand how GenServer handles synchronous and asynchronous requests.', 'order': 2},
                    {'title': 'Supervisor Trees', 'content': 'Supervisors are special processes that monitor and restart child processes when they fail. Learn different restart strategies (one_for_one, one_for_all, rest_for_one), how to design supervision trees, and best practices for building resilient process hierarchies that can recover from any failure.', 'order': 3}
                ]
            },
            {
                'title': 'Concurrent Programming with Erlang',
                'description': 'Dive deep into Erlang\'s lightweight processes and message passing. Learn how to build highly concurrent applications that can handle millions of processes efficiently using the actor model.',
                'cover_image_url': 'https://images.unsplash.com/photo-1518186285589-2f7649de83e0?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1374&q=80',
                'interests': [concurrent_interest, erlang_fundamentals],
                'lessons': [
                    {'title': 'Processes and Message Passing', 'content': 'Learn how to spawn processes using spawn/1 and spawn/3, send messages with the ! operator, and receive messages using receive blocks. Understand process isolation, the shared-nothing architecture, and how Erlang processes differ from OS threads. Build practical examples of concurrent systems.', 'order': 1},
                    {'title': 'Process Links and Monitors', 'content': 'Discover how to create relationships between processes using links and monitors. Learn the difference between link/1 and monitor/2, how to handle process exits, and when to use each mechanism. Understand how these tools enable fault detection and recovery in distributed systems.', 'order': 2},
                    {'title': 'Designing for Concurrency', 'content': 'Learn design patterns for concurrent systems including worker pools, producer-consumer patterns, and load balancing. Understand how to avoid common pitfalls like message queue overflow and how to design systems that scale linearly with the number of cores and nodes.', 'order': 3}
                ]
            },
            {
                'title': 'Building Distributed Systems',
                'description': 'Learn how to build distributed applications that span multiple nodes. Master Erlang\'s built-in distribution capabilities, clustering, and fault tolerance across network boundaries.',
                'cover_image_url': 'https://images.unsplash.com/photo-1509228627152-72ae9ae6848d?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&q=80',
                'interests': [distributed_interest, otp_interest],
                'lessons': [
                    {'title': 'Node Communication', 'content': 'Learn how to set up Erlang nodes, establish connections between them, and send messages across the network. Understand node naming conventions, cookies for security, and how to monitor node connectivity. Build a simple distributed application with multiple nodes.', 'order': 1},
                    {'title': 'Global Process Registry', 'content': 'Discover how to register processes globally across a cluster using global:register_name/2 and global:whereis_name/1. Learn about name conflicts, split-brain scenarios, and how Erlang handles network partitions. Implement a distributed service that can run on any node in the cluster.', 'order': 2},
                    {'title': 'Distributed Database with Mnesia', 'content': 'Learn how to use Mnesia, Erlang\'s distributed database, to store and replicate data across nodes. Understand table types, replication strategies, and transaction handling. Build a fault-tolerant distributed application with persistent data storage that survives node failures.', 'order': 3}
                ]
            },
            {
                'title': 'Telecom Systems Development',
                'description': 'Learn how to build telecom applications using Erlang',
                'cover_image_url': 'https://images.unsplash.com/photo-1563227812-0ea4c22e6cc8?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&q=80',
                'interests': [telecom_interest],
                'lessons': [
                    {'title': 'Protocol Implementation', 'content': 'Learn how to implement network protocols in Erlang using gen_tcp and gen_udp. Understand binary pattern matching for parsing protocol messages, state machines for protocol handling, and how to build robust protocol stacks. Implement a simple HTTP server and client from scratch.', 'order': 1},
                    {'title': 'Real-time Systems', 'content': 'Discover how to build real-time systems with guaranteed response times using Erlang. Learn about soft real-time vs hard real-time requirements, how to measure and optimize latency, and techniques for handling high-throughput message processing. Build a real-time messaging system.', 'order': 2},
                    {'title': 'High Availability Architecture', 'content': 'Learn how to design systems with 99.999% uptime using Erlang/OTP principles. Understand hot code loading, graceful upgrades, redundancy patterns, and failover mechanisms. Study real-world case studies from telecom companies and implement a highly available service that can be upgraded without downtime.', 'order': 3}
                ]
            },
            {
                'title': 'Fun Programming Adventures',
                'description': 'Entertaining programming content with videos and interactive examples',
                'cover_image_url': 'https://images.unsplash.com/photo-1563227812-0ea4c22e6cc8?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&q=80',
                'interests': [fun_interest],
                'lessons': [
                    {'title': 'Programming Games with Erlang', 'content': '''<h3>Fun with Erlang Games</h3>
                            <p>Let's explore how to create simple games using Erlang!</p>
                            <p>This lesson includes interactive examples and video demonstrations.</p>''', 'order': 1, 'content_type': 'video', 'video_url': 'https://www.youtube.com/embed/dQw4w9WgXcQ'},
                    {'title': 'Creative Coding Challenges', 'content': '''<h3>Coding Challenges</h3>
                            <p>Solve fun programming puzzles and challenges!</p>''', 'order': 2, 'content_type': 'mixed', 'video_url': 'https://www.youtube.com/embed/dQw4w9WgXcQ'}
                ]
            }
        ]

        if erlang_fundamentals and otp_interest and concurrent_interest and distributed_interest and telecom_interest and fun_interest:
            print("All interests found. Proceeding to create courses.")
        else:
            print("Not all required interests were found. Skipping course creation.")
            return

        for course_data in courses:
            # Check if course already exists
            existing_course = Course.query.filter_by(title=course_data['title']).first()
            if existing_course:
                print(f"Course '{course_data['title']}' already exists")
                continue

            print(f"Creating course: {course_data['title']}")
            course = Course(
                title=course_data['title'],
                description=course_data['description'],
                cover_image_url=course_data.get('cover_image_url', ''),
                created_by=admin.id
            )
            db.session.add(course)
            db.session.flush()  # Get the course ID

            # Add course-interest relationships
            for interest in course_data['interests']:
                course_interest = CourseInterest(
                    course_id=course.id,
                    interest_id=interest.id,
                    created_by=admin.id
                )
                db.session.add(course_interest)

            # Add lessons
            for lesson_data in course_data['lessons']:
                lesson = Lesson(
                    title=lesson_data['title'],
                    content=lesson_data['content'],
                    course_id=course.id,
                    order=lesson_data['order'],
                    content_type=lesson_data.get('content_type', 'text'),
                    video_url=lesson_data.get('video_url')
                )
                db.session.add(lesson)

        # Commit all changes
        db.session.commit()
        print("Successfully created courses and lessons!")

        # Verify created courses
        courses = Course.query.all()
        print(f"Total courses in database: {len(courses)}")
        for course in courses:
            print(f"- {course.title}")

    except Exception as e:
        db.session.rollback()
        print(f"Error creating courses: {e}")

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        create_sample_courses()
        print("Database setup complete.")