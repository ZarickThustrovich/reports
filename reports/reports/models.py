from django.db import models


class Projects(models.Model):
    name = models.CharField(max_length=100)
    active = models.BooleanField(default=True)    

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Проект'
        verbose_name_plural = 'Проекты'


class Hours(models.Model):
    employee = models.CharField(max_length=100)
    hours = models.CharField(max_length=100)
    datetime = models.DateTimeField()
    project = models.ForeignKey(Projects, on_delete=models.CASCADE)
    comment = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return str(self.project) + '|' + str(self.employee) + '|' + str(self.hours)

    class Meta:
        verbose_name = 'Отчет по проекту'
        verbose_name_plural = 'Отчет по проектам'
    