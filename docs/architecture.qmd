---
title: "Architecture"
---

## Data flow

This application uses a Post-Redirect-Get (PRG) pattern. The user submits a form, which sends a POST request to a FastAPI endpoint on the server. The database is updated, and the user is redirected to a GET endpoint, which fetches the updated data and re-renders the Jinja2 page template with the new data.

``` {python}
#| echo: false
#| include: false
from graphviz import Digraph

dot = Digraph()
dot.attr(rankdir='TB')
dot.attr('node', shape='box', style='rounded')

# Create client subgraph at top
with dot.subgraph(name='cluster_client') as client:
    client.attr(label='Client')
    client.attr(rank='topmost')
    client.node('A', 'User submits form', fillcolor='lightblue', style='rounded,filled')
    client.node('B', 'HTML/JS form validation', fillcolor='lightblue', style='rounded,filled')

# Create server subgraph below
with dot.subgraph(name='cluster_server') as server:
    server.attr(label='Server')
    server.node('C', 'FastAPI request validation in route signature', fillcolor='lightgreen', style='rounded,filled')
    server.node('D', 'Business logic validation in route function body', fillcolor='lightgreen', style='rounded,filled')
    server.node('E', 'Update database', fillcolor='lightgreen', style='rounded,filled')
    server.node('F', 'Middleware error handler', fillcolor='lightgreen', style='rounded,filled')
    server.node('G', 'Render error template', fillcolor='lightgreen', style='rounded,filled')
    server.node('H', 'Redirect to GET endpoint', fillcolor='lightgreen', style='rounded,filled')
    server.node('I', 'Fetch updated data', fillcolor='lightgreen', style='rounded,filled')
    server.node('K', 'Re-render Jinja2 page template', fillcolor='lightgreen', style='rounded,filled')

with dot.subgraph(name='cluster_client_post') as client_post:
    client_post.attr(label='Client')
    client_post.attr(rank='bottommost')
    client_post.node('J', 'Display rendered page', fillcolor='lightblue', style='rounded,filled')

# Add visible edges
dot.edge('A', 'B')
dot.edge('B', 'A')
dot.edge('B', 'C', label='POST Request to FastAPI endpoint')
dot.edge('C', 'D')
dot.edge('C', 'F', label='RequestValidationError')
dot.edge('D', 'E', label='Valid data')
dot.edge('D', 'F', label='Custom Validation Error')
dot.edge('E', 'H', label='Data updated')
dot.edge('H', 'I')
dot.edge('I', 'K')
dot.edge('K', 'J', label='Return HTML')
dot.edge('F', 'G')
dot.edge('G', 'J', label='Return HTML')

dot.render('static/data_flow', format='png', cleanup=True)
```

![Data flow diagram](static/data_flow.png)

The advantage of the PRG pattern is that it is very straightforward to implement and keeps most of the rendering logic on the server side. One disadvantage is that it requires an extra round trip to the database to fetch the updated data, and re-rendering the entire page template may be less efficient than a partial page update on the client side. Another disadvantage is that it if the user makes an invalid form submission, they will see an error page and will have to click the browser's "back" button to get back to the form with their original form inputs.

A future iteration of this application will use HTMX to update the page in place, so that on an invalid submission an error toast is displayed without a page reload (thus preserving the user's scroll position and form inputs).