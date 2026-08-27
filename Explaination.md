# Problem 3: Go Code Explanation

## The code in question

```go
package main
import "fmt"
func main() {
    cnp := make(chan func(), 10)
    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
            }
        }()
    }
    cnp <- func() {
        fmt.Println("HERE1")
    }
    fmt.Println("Hello")
}
```

## 1. How the highlighted constructs work

- **`chan func()`** — a channel whose values are functions. You can send a
  function as a value over this channel, and whoever receives it can call it
  later. This is what allows tasks/jobs to be represented as first-class
  values and dispatched to different goroutines.
- **`go func() { ... }()`** — starts an anonymous function as a new
  goroutine: a lightweight, concurrently scheduled unit of execution managed
  by the Go runtime (not a full OS thread). The `go` keyword launches it and
  returns immediately without waiting for it to finish.
- **`for f := range cnp`** — continuously receives values from the channel
  until it is closed. Each received value `f` is a function, and `f()`
  invokes it.

## 2. Use-cases of these constructs

This is the classic **worker pool** pattern. A fixed number of worker
goroutines all read from the same channel. Jobs (here, closures) are pushed
onto the channel, and whichever worker is free picks one up and runs it.
This is used to process bounded amounts of concurrent work — for example,
handling incoming requests, processing uploads, or sending emails — without
spawning an unbounded number of goroutines for every task.

## 3. Significance of the `for i := 0; i < 4; i++` loop

This loop creates exactly **4 worker goroutines**, all listening on the
same channel `cnp`. This caps concurrency at 4: no matter how many jobs are
sent to the channel, at most 4 will be processed at the same time.

## 4. Significance of `make(chan func(), 10)`

This creates a **buffered channel** with capacity 10. A buffered channel
allows up to 10 sends (`cnp <- ...`) to happen without blocking, even if no
worker is currently ready to receive. If the channel were unbuffered
(`make(chan func())`), a send would block until some goroutine was ready to
receive it right at that moment — which, combined with the fact that the
worker goroutines may not have started running yet, would make timing even
less predictable.

## 5. Why "HERE1" does not get printed

This is the core subtlety of the program: **`main()` does not wait for any
goroutines to finish.** In Go, once `main()` returns, the entire program
exits immediately, regardless of what any other goroutines are doing.

Walking through execution:

1. Four worker goroutines are started, but the Go scheduler is not
   guaranteed to have actually run any of them yet.
2. `cnp <- func(){...}` succeeds immediately without blocking, since the
   channel has buffer space (10 slots, only 1 used).
3. `fmt.Println("Hello")` executes right after.
4. `main()` returns, and the program exits — killing any goroutine that
   has not finished (or even started) running, including whichever worker
   would have eventually pulled the function off the channel and called it.

So there is a race: `"Hello"` is guaranteed to print (it runs synchronously
in `main`), but `"HERE1"` printing depends on whether the Go scheduler
happened to run one of the four worker goroutines, have it dequeue the
function, and call it — all before `main()` returned. This is not
guaranteed, and in practice, printing "Hello" and returning from `main`
usually happens faster than the OS scheduler gets around to running a new
goroutine, so `"HERE1"` is typically never printed.

### How to make "HERE1" print reliably

Add synchronization so `main()` waits before returning, for example using a
`sync.WaitGroup`:

```go
package main

import (
	"fmt"
	"sync"
)

func main() {
	cnp := make(chan func(), 10)
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		go func() {
			for f := range cnp {
				f()
			}
		}()
	}

	wg.Add(1)
	cnp <- func() {
		defer wg.Done()
		fmt.Println("HERE1")
	}

	fmt.Println("Hello")
	wg.Wait() // block until the job signals it's done
	close(cnp)
}
```

This guarantees `main()` does not exit until the submitted job has actually
run and printed "HERE1".