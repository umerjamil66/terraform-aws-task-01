output "load_balancer_dns" {
  value = aws_lb.my_alb.dns_name
}

output "nginx_public_ip" {
  value = aws_instance.nginx-server.public_ip
}